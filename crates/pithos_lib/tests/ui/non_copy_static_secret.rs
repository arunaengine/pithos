use pithos_lib::crypto::generate_private_key;

fn main() {
    let secret = generate_private_key();
    let _moved = secret;
    let _used_after_move = secret;
}
