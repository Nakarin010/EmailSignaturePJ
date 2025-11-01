"""
End‑to‑end demo:
    • Users keep their own key pair under KEYS/<user>/
    • Inside KEYS/<user>/public_keys/ lives the key‑ring with everyone else’s public keys
    • sender_flow() ⇒ sign and store the outgoing message
    • receiver_flow() ⇒ verify a message that was saved by the sender

"""
import pyfiglet
import json
import hashlib
import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
#  Utility helpers (file IO) read and write files
# ---------------------------------------------------------------------------

def _ensure_user_dirs(user: str) -> str:
    """Return KEYS/<user> folder path, creating it (and key‑ring sub folder) if needed."""
    folder = os.path.join("KEYS", user)
    os.makedirs(os.path.join(folder, "public_keys"), exist_ok=True)
    return folder


def _save_keypair(user: str, priv_key, pub_key) -> None:
    folder = _ensure_user_dirs(user)
    with open(os.path.join(folder, "private_key.pem"), "wb") as fh:
        fh.write(
            priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(os.path.join(folder, f"{user}_public_key.pem"), "wb") as fh:
        fh.write(
            pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def _load_priv_from_file(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def _load_pub_from_file(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_public_key(fh.read())


# ---------------------------------------------------------------------------
#  Key management (own keys and key‑ring)
# ---------------------------------------------------------------------------

def generate_keys(key_size: int):
    prv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return prv, prv.public_key()


def generate_or_load_own_keys(user: str, key_size: int):
    folder = _ensure_user_dirs(user)
    priv_p = os.path.join(folder, "private_key.pem")
    pub_p = os.path.join(folder, f"{user}_public_key.pem")

    if os.path.exists(priv_p) and os.path.exists(pub_p):
        print(f"🔑 Loading existing keys for {user} …")
        return _load_priv_from_file(priv_p), _load_pub_from_file(pub_p)

    print(f"🔐 GENERATING KEY PAIR FOR {user} …")
    prv, pub = generate_keys(key_size)
    _save_keypair(user, prv, pub)
    return prv, pub


def add_public_key_to_keyring(holder: str, other: str) -> bool:
    """Copy <other>'s public key into <holder>'s key‑ring if missing."""
    src = os.path.join("KEYS", other, f"{other}_public_key.pem")
    dst = os.path.join("KEYS", holder, "public_keys", f"{other}_public_key.pem")

    if not os.path.exists(src):
        print(f"❌ {other}'s public key does not exist – ask them to run sender_flow once.")
        return False

    if not os.path.exists(dst):
        _ensure_user_dirs(holder)
        with open(src, "rb") as s, open(dst, "wb") as d:
            d.write(s.read())
        print(f"🔑 Added {other}'s public key to {holder}'s key‑ring.")
    return True


def load_public_from_keyring(holder: str, other: str):
    path = os.path.join("KEYS", holder, "public_keys", f"{other}_public_key.pem")
    return _load_pub_from_file(path) if os.path.exists(path) else None


# ---------------------------------------------------------------------------
#  Crypto primitives (sign / verify)
# ---------------------------------------------------------------------------
def sign_email(prv_key, body: str) -> bytes:
    #32 bytes fixed length hash
    digest = hashlib.sha256(body.encode()).digest()#hash the email body first
    # then return the 
    return prv_key.sign(
        #.digest() will return a binary hash
        #then sign the hash with the private key 
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), #mask generation function
            salt_length=padding.PSS.MAX_LENGTH, #randomness to prevent reuse problems
        ),
        hashes.SHA256(),
    )
# ---------------------------------------------------------------------------
#  Verify the signature
# -----------------------------------------------------------------------------
def verify_signature(pub_key, body: str, sig: bytes) -> bool:
    digest = hashlib.sha256(body.encode()).digest()
    try:
        # verify the signature with public key of sender
        # .verify() automatically decrypt hash and compare it with the hash of the email body
        pub_key.verify(
            sig, 
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# JSON the ADDRESS BOOK
# ---------------------------------------------------------------------------
ADDRESS_BOOK_PATH = "address_book.json"

def load_address_book():
    if os.path.exists(ADDRESS_BOOK_PATH):
        with open(ADDRESS_BOOK_PATH, "r") as f:
            return json.load(f)
    return {}

def save_address_book(book):
    with open(ADDRESS_BOOK_PATH, "w") as f:
        json.dump(book, f, indent=4)

# ---------------------------------------------------------------------------
#  Simple address‑book for the demo
# ---------------------------------------------------------------------------
ex = load_address_book()
# ---------------------------------------------------------------------------
#  CLI flows
# ---------------------------------------------------------------------------

def sender_flow():
    key_size = int(input("Enter RSA key size (2048, 3072, 4096): "))
    if key_size not in {2048, 3072, 4096}:
        print("❌ Invalid key size.")
        return

    print("👊 \U0001F1FA\U0001F1F8 🔥BRO!")
    user = input("ENTER YOUR USERNAME: ").lower()
    if user not in ex:
        ex[user] = input("Enter your email address: ")
        save_address_book(ex)

    prv, _ = generate_or_load_own_keys(user, key_size)

    sender_addr = ex[user]
    print(f"✅ user matched email: '{user}' : '{sender_addr}' ")

    to_addr = input("Enter the recipient's email address: ").lower()
    recipient = next((u for u, mail in ex.items() if mail == to_addr), None)
    if recipient is None:
        recipient = input("Recipient not in address‑book – enter their username: ").lower()
        ex[recipient] = to_addr
        save_address_book(ex)
        generate_or_load_own_keys(recipient, key_size)  # pre‑create their keys for demo

    add_public_key_to_keyring(user, recipient)

    subject = input("Enter the subject of the email: ")
    body = input("Enter the email body to sign: ")

    sig = sign_email(prv, body)

    print("\n================================================")
    print(f"From: {sender_addr}")
    print(f"To: {to_addr}")
    print(f"Subject: {subject}")
    print(body)
    print(f"Date: {datetime.datetime.now()}")
    print("================================================")
    print("✅ Digital signature created (hex):\n", sig.hex())

    with open("signed_email.txt", "w") as fh:
        fh.write(
            f"From: {sender_addr}\nTo: {to_addr}\nSubject: {subject}\nDate: {datetime.datetime.now()}\nEmail Body:\n{body}\nDigital Signature (Hex):\n{sig.hex()}\n"
        )
    print("📝 Email and signature saved to 'signed_email.txt'")


def receiver_flow():
    user = input("ENTER YOUR USERNAME (receiver): ").lower()
    if user not in ex:
        print("❌ You are not in the address‑book")
        return
        # recepient = input("Recipient not in address‑book – enter their username: ").lower()
        # save_address_book(ex)

    
    generate_or_load_own_keys(user, 2048)  # make sure receiver has a key‑ring folder

    if not os.path.exists("signed_email.txt"):
        print("❌ signed_email.txt not found – run the sender flow first.")
        return

    # Parse the saved file ---------------------------------------------------
    with open("signed_email.txt") as fh:
        lines = fh.read().splitlines()
    headers = {k.lower(): v for k, v in (ln.split(": ", 1) for ln in lines[:4])}
    body_start = lines.index("Email Body:") + 1
    sig_idx = lines.index("Digital Signature (Hex):") + 1
    body = "\n".join(lines[body_start : sig_idx - 1])
    sig = bytes.fromhex(lines[sig_idx].strip())

    # in the process of getting the sender identity
    # which later will be used 
    sender_addr = headers["from"]
    #next() will return the first item in the iterator
    sender_user = next((u for u, mail in ex.items() if mail == sender_addr), None)
    if sender_user is None:
        print("❌ Sender unknown.")
        return

    pub = load_public_from_keyring(user, sender_user)
    if pub is None:
        print(f"❌ {sender_user}'s public key not in your key‑ring. Adding …")
        if not add_public_key_to_keyring(user, sender_user):
            return
        pub = load_public_from_keyring(user, sender_user)
        
        
    # testing against every known public key
    print("\n🧪 Testing signature against every known public key...")
    for other_user in ex.keys():
        test_pub = load_public_from_keyring(user, other_user)
        if test_pub is None:
            print(f"⚠️ No key for {other_user}")
            continue

        is_valid = verify_signature(test_pub, body, sig)
        status = "✅ VALID" if is_valid else "❌ INVALID"
        print(f"🔍 Tested with {other_user}'s key: {status}")
    
    # Verify ----------------------------------------------------------------
    if verify_signature(pub, body, sig):
        print("✅ Signature is VALID. Email is authentic.\n")
    else:
        print("❌ Signature is INVALID – the email may have been altered or authenticiy may be compromised.\n")
        return

    print("================================================")
    print("📧 THE EMAIL")
    print("------------------------------------------------")
    for k in ("from", "to", "subject", "date"):
        print(f"{k.title()}: {headers[k]}")
    print("\n" + body)
    print("================================================")
    print("🔑 THE SIGNATURE (hex)")
    print(sig.hex())


# ---------------------------------------------------------------------------

def main():
    print(pyfiglet.figlet_format("Mailing"))
    print("1. Sign Email (Sender)")
    print("2. Verify Email (Receiver)")
    choice = input("Choose (1 or 2): ")
    if choice == "1":
        sender_flow()
    elif choice == "2":
        receiver_flow()
    else:
        print("❌ Invalid choice.")


if __name__ == "__main__":
    main()
