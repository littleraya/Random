    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def read_message() -> str:
    if sys.stdin.isatty():
        message = input(f"[Alice] Ketik pesan (Enter untuk default): ").strip()
        return message or DEFAULT_MESSAGE
    return DEFAULT_MESSAGE


def main() -> None:
    alice_private = generate_key_pair()
    bob_private = generate_key_pair()

    alice_public_hex = public_hex(alice_private)
    bob_public_hex = public_hex(bob_private)

    alice_shared_secret = alice_private.exchange(bob_private.public_key())
    bob_shared_secret = bob_private.exchange(alice_private.public_key())

    alice_session_key = derive_session_key(alice_shared_secret)
    bob_session_key = derive_session_key(bob_shared_secret)

    message = read_message()
    nonce, ciphertext = encrypt_message(alice_session_key, message)
    decrypted_message = decrypt_message(bob_session_key, nonce, ciphertext)

    new_alice_private = generate_key_pair()
    new_shared_secret = new_alice_private.exchange(bob_private.public_key())
    new_session_key = derive_session_key(new_shared_secret)

    try:
        decrypt_message(new_session_key, nonce, ciphertext)
        isolation_result = "bisa dekripsi pesan lama"
    except InvalidTag:
        isolation_result = "tidak bisa dekripsi pesan lama"

    print(f"[Alice] Public Key: {short_hex(bytes.fromhex(alice_public_hex))}")
    print(f"[Bob]   Public Key: {short_hex(bytes.fromhex(bob_public_hex))}")
    print()
    print(
        "[Shared Secret] Alice: "
        f"{short_hex(alice_shared_secret)} | Bob: {short_hex(bob_shared_secret)} "
        f"({'sama' if alice_shared_secret == bob_shared_secret else 'berbeda'})"
    )
    print(
        "[Session Key]   Alice: "
        f"{short_hex(alice_session_key)} | Bob: {short_hex(bob_session_key)} "
        f"({'sama' if alice_session_key == bob_session_key else 'berbeda'})"
    )
    print()
    print(f'[Alice] Pesan asli: "{message}"')
    print(f"[Alice] Ciphertext: nonce={nonce.hex()} ct={ciphertext.hex()}")
    print(f'[Bob]   Terdekripsi: "{decrypted_message}" [OK]')
    print()
    print(
        "[Session baru] Key berbeda: "
        f"{short_hex(new_session_key)} <- {isolation_result}"
    )


if __name__ == "__main__":
    main()