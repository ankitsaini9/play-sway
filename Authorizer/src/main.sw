contract;


use std::{
    contract_id::ContractId,
    address::Address,
    option::Option,
    assert::{assert ,require},
    vec::Vec,
    context::balance_of,
    chain::auth::{AuthError, msg_sender},
    identity::Identity,
    result::*,
    context::call_frames::contract_id,
    storage::{StorageMap,get, store},
    revert::revert,
};


use InputHelpers::ensure_input_length_match;


struct AddressSet {
    // Storage of set values
    _values: Vec<Address>,
    // Position of the value in the `values` array, plus 1 because index 0
    // means a value is not in the set.
    _indexes: StorageMap<Address, u64>,
}

struct RoleData {
    members: AddressSet,
    adminRole: b256,
}

storage {
    _roles: StorageMap<b256, RoleData> = StorageMap{},
}

abi Authorizer {
    #[storage(read)]fn can_perform(actionId: b256, account: Address) -> bool;
    #[storage(write, read)]fn grant_roles(roles: Vec<b256>, account: Address);
    #[storage(write, read)]fn grant_roles_to_many(roles: Vec<b256>, accounts: Vec<Address>);
    #[storage(write, read)]fn revoke_roles(roles: Vec<b256>, account: Address);
    #[storage(write, read)]fn revoke_roles_from_many(roles: Vec<b256>, accounts: Vec<Address>);
}


/**
    * @dev Returns `true` if `account` has been granted `role`.
    */
#[storage(read)]
fn has_role(role: b256, account: Address) -> bool {
    let mut count = 0;
    while count < storage._roles.get(role).members._values.len() {
        if storage._roles.get(role).members._values.get(count).unwrap() == account {
            return true;
        }
        count = count + 1;
    }
    return false;
}

/**
    * @dev Grants `role` to `account`.
    *
    * If `account` had not been already granted `role`, emits a {RoleGranted}
    * event.
    *
    * Requirements:
    *
    * - the caller must have ``role``'s admin role.
    */
#[storage(write, read)]
fn grant_role(role: b256, account: Address) {
    let sender: Result<Identity, AuthError> = msg_sender();
    let sender: Address = match sender.unwrap() {
        Identity::Address(addr) => {
            addr
        },
        _ => {
            revert(0);
        },
    };
    require(has_role(storage._roles.get(role).adminRole, sender), "GRANT_SENDER_NOT_ADMIN");

    _grant_role(role, account);
}

#[storage(write, read)]
fn _grant_role(role: b256, account: Address) {
    let tmp = storage._roles.get(role).members;
    if tmp._indexes.get(account) == 0 {
        tmp._values.push(account);
        tmp._indexes.insert(account, tmp._values.len());
    }
}


impl Authorizer for Contract {
    /**
    * @dev Basic Authorizer implementation, based on OpenZeppelin's Access Control.
    *
    * Users are allowed to perform actions if they have the role with the same identifier. In this sense, roles are not
    * being truly used as such, since they each map to a single action identifier.
    *
    * This temporary implementation is expected to be replaced soon after launch by a more sophisticated one, able to
    * manage permissions across multiple contracts and to natively handle timelocks.
    */
    #[storage(read)]
    fn can_perform(
        actionId: b256,
        account: Address,
        // address
    ) -> bool {
        // This Authorizer ignores the 'where' field completely.
        return has_role(actionId, account);
    }


    /**
     * @dev Grants multiple roles to a single account.
     */
    #[storage(write, read)]
    fn grant_roles(roles: Vec<b256>, account: Address) {
        let mut count = 0;
        while count < roles.len() {
            grant_role(roles.get(count).unwrap(), account);
            count = count + count;
        }
    }

    /**
     * @dev Grants roles to a list of accounts.
     */
    #[storage(write, read)]
    fn grant_roles_to_many(roles: Vec<b256>, accounts: Vec<Address>) {
        ensure_input_length_match(roles.len(), accounts.len());
        let mut count = 0;
        while count < roles.len() {
            grant_role(roles.get(count).unwrap(), accounts.get(count).unwrap());
            count = count + count;
        }
    }

    /**
     * @dev Revokes multiple roles from a single account.
     */
    #[storage(write, read)]
    fn revoke_roles(roles: Vec<b256>, account: Address) {
        let mut count = 0;
        while count < roles.len() {
            grant_role(roles.get(count).unwrap(), account);
            count = count + count;
        }
    }

    /**
     * @dev Revokes roles from a list of accounts.
     */
    #[storage(write, read)]
    fn revoke_roles_from_many(roles: Vec<b256>, accounts: Vec<Address>) {
        ensure_input_length_match(roles.len(), accounts.len());
        let mut count = 0;
        while count < roles.len() {
            grant_role(roles.get(count).unwrap(), accounts.get(count).unwrap());
            count = count + count;
        }
    }
}
