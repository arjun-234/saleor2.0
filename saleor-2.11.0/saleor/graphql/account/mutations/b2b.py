from collections import defaultdict
from copy import copy

import graphene
from django.core.exceptions import ValidationError
from django.db import transaction

from ....account import events as account_events, models, utils
from ....account.emails import send_set_password_email_with_url
from ....account.error_codes import AccountErrorCode
from ....account.thumbnails import create_user_avatar_thumbnails
from ....account.utils import remove_staff_member
from ....checkout import AddressType
from ....core.exceptions import PermissionDenied
from ....core.permissions import AccountPermissions
from ....core.utils.url import validate_storefront_url
from ...account.enums import AddressTypeEnum
from ...account.types import Address, AddressInput, User
from ...core.mutations import BaseMutation, ModelDeleteMutation, ModelMutation
from ...core.types import Upload
from ...core.types.common import AccountError, StaffError, B2bError
from ...core.utils import get_duplicates_ids, validate_image_file
from ...decorators import staff_member_required
from ...meta.deprecated.mutations import ClearMetaBaseMutation, UpdateMetaBaseMutation
from ..utils import (
    CustomerDeleteMixin,
    B2bDeleteMixin,
    UserDeleteMixin,
    get_groups_which_user_can_manage,
    get_not_manageable_permissions_when_deactivate_or_remove_users,
    get_out_of_scope_users,
)
from .base import (
    BaseAddressDelete,
    BaseAddressUpdate,
    BaseCustomerCreate,
    CustomerInput,
    UserInput,
)


class B2bInput(UserInput):
    add_groups = graphene.List(
        graphene.NonNull(graphene.ID),
        description="List of permission group IDs to which user should be assigned.",
        required=False,
    )


class B2bCreateInput(B2bInput):
    redirect_url = graphene.String(
        description=(
            "URL of a view where users should be redirected to "
            "set the password. URL in RFC 1808 format."
        )
    )


class B2bUpdateInput(B2bInput):
    remove_groups = graphene.List(
        graphene.NonNull(graphene.ID),
        description=(
            "List of permission group IDs from which user should be unassigned."
        ),
        required=False,
    )



class B2bCreate(ModelMutation):
    class Arguments:
        input = B2bCreateInput(
            description="Fields required to create a B2b user.", required=True
        )

    class Meta:
        description = "Creates a new b2b user."
        exclude = ["password"]
        model = models.User
        permissions = (AccountPermissions.MANAGE_B2B,)
        error_type_class = B2bError
        error_type_field = "b2b_errors"

    @classmethod
    def clean_input(cls, info, instance, data):
        cleaned_input = super().clean_input(info, instance, data)

        errors = defaultdict(list)
        if cleaned_input.get("redirect_url"):
            try:
                validate_storefront_url(cleaned_input.get("redirect_url"))
            except ValidationError as error:
                error.code = AccountErrorCode.INVALID
                errors["redirect_url"].append(error)

        requestor = info.context.user
        # set is_staff to True to create a staff user
        cleaned_input["is_b2b"] = True
        cls.clean_groups(requestor, cleaned_input, errors)
        cls.clean_is_active(cleaned_input, instance, info.context.user, errors)

        if errors:
            raise ValidationError(errors)
        return cleaned_input

    @classmethod
    def clean_groups(cls, requestor: models.User, cleaned_input: dict, errors: dict):
        if cleaned_input.get("add_groups"):
            cls.ensure_requestor_can_manage_groups(
                requestor, cleaned_input, "add_groups", errors
            )

    @classmethod
    def ensure_requestor_can_manage_groups(
        cls, requestor: models.User, cleaned_input: dict, field: str, errors: dict
    ):
        """Check if requestor can manage group.

        Requestor cannot manage group with wider scope of permissions.
        """
        if requestor.is_superuser:
            return
        groups = cleaned_input[field]
        user_editable_groups = get_groups_which_user_can_manage(requestor)
        out_of_scope_groups = set(groups) - set(user_editable_groups)
        if out_of_scope_groups:
            # add error
            ids = [
                graphene.Node.to_global_id("Group", group.pk)
                for group in out_of_scope_groups
            ]
            error_msg = "You can't manage these groups."
            code = AccountErrorCode.OUT_OF_SCOPE_GROUP.value
            params = {"groups": ids}
            error = ValidationError(message=error_msg, code=code, params=params)
            errors[field].append(error)

    @classmethod
    def clean_is_active(cls, cleaned_input, instance, request, errors):
        pass

    @classmethod
    def save(cls, info, user, cleaned_input):
        user.save()
        if cleaned_input.get("redirect_url"):
            send_set_password_email_with_url(
                redirect_url=cleaned_input.get("redirect_url"), user=user, staff=False , b2b=True
            )

    @classmethod
    @transaction.atomic
    def _save_m2m(cls, info, instance, cleaned_data):
        super()._save_m2m(info, instance, cleaned_data)
        groups = cleaned_data.get("add_groups")
        if groups:
            instance.groups.add(*groups)


class B2bUpdate(B2bCreate):
    class Arguments:
        id = graphene.ID(description="ID of a b2b user to update.", required=True)
        input = B2bUpdateInput(
            description="Fields required to update a b2b user.", required=True
        )

    class Meta:
        description = "Updates an existing b2b user."
        exclude = ["password"]
        model = models.User
        permissions = (AccountPermissions.MANAGE_B2B,)
        error_type_class = B2bError
        error_type_field = "b2b_errors"

    @classmethod
    def clean_input(cls, info, instance, data):
        requestor = info.context.user
        # check if requestor can manage this user
        if not requestor.is_superuser and get_out_of_scope_users(requestor, [instance]):
            msg = "You can't manage this user."
            code = AccountErrorCode.OUT_OF_SCOPE_USER.value
            raise ValidationError({"id": ValidationError(msg, code=code)})

        cls.check_for_duplicates(data)

        cleaned_input = super().clean_input(info, instance, data)

        return cleaned_input

    @classmethod
    def check_for_duplicates(cls, input_data):
        duplicated_ids = get_duplicates_ids(
            input_data.get("add_groups"), input_data.get("remove_groups")
        )
        if duplicated_ids:
            # add error
            msg = (
                "The same object cannot be in both list"
                "for adding and removing items."
            )
            code = AccountErrorCode.DUPLICATED_INPUT_ITEM.value
            params = {"groups": duplicated_ids}
            raise ValidationError(msg, code=code, params=params)

    @classmethod
    def clean_groups(cls, requestor: models.User, cleaned_input: dict, errors: dict):
        if cleaned_input.get("add_groups"):
            cls.ensure_requestor_can_manage_groups(
                requestor, cleaned_input, "add_groups", errors
            )
        if cleaned_input.get("remove_groups"):
            cls.ensure_requestor_can_manage_groups(
                requestor, cleaned_input, "remove_groups", errors
            )

    @classmethod
    def clean_is_active(
        cls,
        cleaned_input: dict,
        instance: models.User,
        requestor: models.User,
        errors: dict,
    ):
        is_active = cleaned_input.get("is_active")
        if is_active is None:
            return
        if not is_active:
            cls.check_if_deactivating_superuser_or_own_account(
                instance, requestor, errors
            )
            cls.check_if_deactivating_left_not_manageable_permissions(
                instance, requestor, errors
            )

    @classmethod
    def check_if_deactivating_superuser_or_own_account(
        cls, instance: models.User, requestor: models.User, errors: dict
    ):
        """User cannot deactivate superuser or own account.

        Args:
            instance: user instance which is going to deactivated
            requestor: user who performs the mutation
            errors: a dictionary to accumulate mutation errors

        """
        if requestor == instance:
            error = ValidationError(
                "Cannot deactivate your own account.",
                code=AccountErrorCode.DEACTIVATE_OWN_ACCOUNT.value,
            )
            errors["is_active"].append(error)
        elif instance.is_superuser:
            error = ValidationError(
                "Cannot deactivate superuser's account.",
                code=AccountErrorCode.DEACTIVATE_SUPERUSER_ACCOUNT.value,
            )
            errors["is_active"].append(error)

    @classmethod
    def check_if_deactivating_left_not_manageable_permissions(
        cls, user: models.User, requestor: models.User, errors: dict
    ):
        """Check if after deactivating user all permissions will be manageable.

        After deactivating user, for each permission, there should be at least one
        active staff member who can manage it (has both “manage staff” and
        this permission).
        """
        if requestor.is_superuser:
            return
        permissions = get_not_manageable_permissions_when_deactivate_or_remove_users(
            [user]
        )
        if permissions:
            # add error
            msg = (
                "Users cannot be deactivated, some of permissions "
                "will not be manageable."
            )
            code = AccountErrorCode.LEFT_NOT_MANAGEABLE_PERMISSION.value
            params = {"permissions": permissions}
            error = ValidationError(msg, code=code, params=params)
            errors["is_active"].append(error)

    @classmethod
    @transaction.atomic
    def _save_m2m(cls, info, instance, cleaned_data):
        super()._save_m2m(info, instance, cleaned_data)
        add_groups = cleaned_data.get("add_groups")
        if add_groups:
            instance.groups.add(*add_groups)
        remove_groups = cleaned_data.get("remove_groups")
        if remove_groups:
            instance.groups.remove(*remove_groups)

class UserDelete(UserDeleteMixin, ModelDeleteMutation):
    class Meta:
        abstract = True

class B2bDelete(B2bDeleteMixin, UserDelete):
    class Meta:
        description = "Deletes a B2b user."
        model = models.User
        permissions = (AccountPermissions.MANAGE_B2B,)
        error_type_class = B2bError
        error_type_field = "b2b_errors"

    class Arguments:
        id = graphene.ID(required=True, description="ID of a b2b user to delete.")

    @classmethod
    def perform_mutation(cls, _root, info, **data):
        if not cls.check_permissions(info.context):
            raise PermissionDenied()

        user_id = data.get("id")
        instance = cls.get_node_or_error(info, user_id, only_type=User)
        cls.clean_instance(info, instance)

        db_id = instance.id
        remove_staff_member(instance)
        # After the instance is deleted, set its ID to the original database's
        # ID so that the success response contains ID of the deleted object.
        instance.id = db_id
        return cls.success_response(instance)