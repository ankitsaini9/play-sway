contract;


use std::{
    address::Address,
    vec::Vec,
};


use InputHelpers::ensure_input_length_match;
use AccessControl::{has_role, grant_role};

abi Authorizer {
    fn grant_roles(roles: Vec<b256>, account: Address);
    fn grant_roles_to_many(roles: Vec<b256>, accounts: Vec<Address>);
    fn revoke_roles(roles: Vec<b256>, account: Address);
    fn revoke_roles_from_many(roles: Vec<b256>, accounts: Vec<Address>);
}

/**
 * @dev Basic Authorizer implementation, based on OpenZeppelin's Access Control.
 *
 * Users are allowed to perform actions if they have the role with the same identifier. In this sense, roles are not
 * being truly used as such, since they each map to a single action identifier.
 *
 * This temporary implementation is expected to be replaced soon after launch by a more sophisticated one, able to
 * manage permissions across multiple contracts and to natively handle timelocks.
 */

fn can_perform(
    actionId: b256,
    account: Address,
    // address
) -> bool {
    // This Authorizer ignores the 'where' field completely.
    return has_role(actionId, account);
}

impl Authorizer for Contract {
    /**
     * @dev Grants multiple roles to a single account.
     */
    fn grant_roles(roles: Vec<b256>, account: Address) {
        let mut count = 0;
        while count < roles.len() {
            // grantRole(roles.get(count).unwrap(), account);
            count = count + count;
        }
    }

    /**
     * @dev Grants roles to a list of accounts.
     */
    fn grant_roles_to_many(roles: Vec<b256>, accounts: Vec<Address>) {
        ensure_input_length_match(roles.len(), accounts.len());
        let mut count = 0;
        while count < roles.len() {
            // grant_role(roles.get(count).unwrap(), accounts.get(count).unwrap());
            count = count + count;
        }
    }

    /**
     * @dev Revokes multiple roles from a single account.
     */
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
    fn revoke_roles_from_many(roles: Vec<b256>, accounts: Vec<Address>) {
        ensure_input_length_match(roles.len(), accounts.len());
        let mut count = 0;
        while count < roles.len() {
            grant_role(roles.get(count).unwrap(), account);
            count = count + count;
        }
    }
}
