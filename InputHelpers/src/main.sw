library InputHelpers; 

use std::{
    assert::require,
    contract_id::ContractId,
    vec::Vec,
    address::Address,
    option::Option,
};

pub fn ensure_input_length_match(a: u64, b: u64) {
    require(a == b, "INPUT_LENGTH_MISMATCH");
}

// fn ensure_input_length_match(a: u64, b: u64, c: u64) {
//     require(a == b && b == c, "INPUT_LENGTH_MISMATCH");
// }

// fn ensure_array_is_sorted(array: Vec<ContractId>) {
//     let addressArray = Vec<Address>;
//     // solhint-disable-next-line no-inline-assembly
//     asm {
//         addressArray := array
//     }
//     ensure_array_is_sorted(addressArray);
// }

fn ensure_array_is_sorted(array: Vec<Address>) {
    if array.len() < 2 {
        return;
    }

    let mut previous = array.get(0).unwrap();
    let mut count = 0;
    while count < array.len() {
        let current = array.get(count).unwrap();
        // require(previous < current, "UNSORTED_ARRAY");
        previous = current;
        count = count + 1;
    }
}

