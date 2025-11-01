import hashlib
import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# some predefined user id and their email addr
ex = {'george': 'doge@bullet.gov', 'nate': 'nate@jacob.hbo', 'ken': "kendall@roy.hbo"}


# old method 
def generate_keys(key_size):
    """
    Generate RSA keys and return private/public key objects.
    """
    #generate the keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# new method with path to keys and check if they exists or not
def generate_or_load_keys(user,key_size):
    """
    Generate RSA keys and return private/public key objects.
    """
    #path to the keys
    user_folder = f"KEYS/{user}"
    priv_path = f"{user_folder}/private_key.pem"
    pub_path = f"{user_folder}/{user}_public_key.pem"
    
    #check if the keys already exist
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        private_key = load_private_key(priv_path)
        public_key = load_public_key(pub_path)
    else:
        print(f'🔐 GENERATING KEYS PAIR FOR {user}')
        private_key, public_key = generate_keys(key_size)
        saved_keys(user,private_key, public_key)
    
    return private_key, public_key

# def saved_keys(user,private_key, public_key):
#     """
#     Save the private and public keys to PEM files.
#     """
#     os.makedirs("KEYS", exist_ok=True)
#     #write the private key to a file with specific user name and path
#     with open(f"KEYS/{user}_private_key.pem", "wb") as f:
#         f.write(private_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.NoEncryption()
#         ))
#     #write the public key to a file
#     with open(f"KEYS/{user}_public_key.pem", "wb") as f:
#         f.write(public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))
    
#key rings system implemented
def saved_keys(user, private_key, public_key):
    user_folder = f"KEYS/{user}"
    os.makedirs(user_folder, exist_ok=True)
    os.makedirs(f"{user_folder}/public_keys", exist_ok=True)

    with open(f"{user_folder}/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"{user_folder}/{user}_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
# add public key to keyring
def add_public_key_to_keyring(user, other_user):
    source = f"KEYS/{other_user}/{other_user}_public_key.pem"
    destination = f"KEYS/{user}/public_keys/{other_user}_public_key.pem"

    if not os.path.exists(source):
        print(f"❌ {other_user}'s public key does not exist.")
        return False

    os.makedirs(f"KEYS/{user}/public_keys", exist_ok=True)

    with open(source, "rb") as src, open(destination, "wb") as dst:
        dst.write(src.read())
    print(f"🔑 Added {other_user}'s public key to {user}'s keyring.")
    return True


#old method no key rings
def load_public_key(path):
    """
    Load the public key from a PEM file.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path):
    """
    Load the private key from a PEM file.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

#key rings method
def load_private_key(user):
    path = f"KEYS/{user}/private_key.pem"
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_from_keyring(user, target_user):
    # Load another user's public key from user's keyring
    path = f"KEYS/{user}/public_keys/{target_user}_public_key.pem"
    if not os.path.exists(path):
        print(f"❌ Public key for {target_user} not in {user}'s keyring.")
        return None
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
    
    
def generate_or_load_own_keys(user, key_size):
    """
    Generate or load your own RSA keys.
    """
    user_folder = f"KEYS/{user}"
    priv_path = f"{user_folder}/private_key.pem"
    pub_path = f"{user_folder}/{user}_public_key.pem"
    
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print(f"🔑 Loading existing keys for {user}.")
        private_key = load_private_key(priv_path)
        public_key = load_public_key(pub_path)
    else:
        print(f"🔐 Generating key pair for {user}.")
        private_key, public_key = generate_keys(key_size)
        saved_keys(user, private_key, public_key)
    
    return private_key, public_key

def sign_email(private_key, email_body):
    """
    Sign the SHA-256 hash of the email body with the private key.
    """
    #.digest() will return a binary hash
    digest = hashlib.sha256(email_body.encode()).digest() #hash the email body first
    #then sign the hash with the private key 
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, email_body, signature):
    """
    Verify the digital signature using the public key and email body.
    """
    digest = hashlib.sha256(email_body.encode()).digest()
    try:
        #verify the signature with the public key by using the .verify() method
        public_key.verify(
            signature,
            digest,
            #pad if message is shorter than block size, with out it it becomes deterministic
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), #mask generation function
                salt_length=padding.PSS.MAX_LENGTH #randomness to prevent reuse problems
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def sender_flow():
    key_size = int(input("Enter RSA key size (2048, 3072, 4096): "))
    if key_size not in [2048, 3072, 4096]:
        print("❌ Invalid key size.")
        return

    print("👊🇺🇸🔥BRO!") #signal gate!!
    user = input("ENTER YOUR USERNAME:")   
    #check if user is in the list of predefined users
    if user not in ex:
        ex[user] = input("Enter your email address: ")

    private_key, public_key = generate_or_load_keys(user,key_size)
    saved_keys(user,private_key, public_key)
    From = ex[user]
    print('✅user matched email: ', From)
    print(f'From: "{From}"')
    # to check whether destination email is exist or not 
    # additionally check for the user if not exists then create new user with keys/
    To_mail = input("Enter the recipient's email address: ")
    To_mail = To_mail.lower()
    
    check_recipient = None
    for useR, email in ex.items():
        if To_mail  == email:
            check_recipient = useR
            break
    # if check_recipient is None:
    #     # if email not exists then create a new user with keys
    #     # then save the keys and just get going with the rest of the flow
    #     check_recipient = input("Enter the recipient's username: ")
    #     ex[check_recipient] = To_mail
    #     print(f'📥 Generating keys for new recipient: {check_recipient}')
    #     receiver_priv_key, receiver_pub_key = generate_or_load_keys(check_recipient, key_size)
    #     saved_keys(check_recipient,receiver_priv_key, receiver_pub_key)
    #     print(f'To: "{check_recipient}"')
    #     Subject = input("Enter the subject of the email: ")
    #     email_body = input("Enter the email body to sign: ")
    #     print("================================================")
    #     print(f'From: "{From}"')
    #     print(f'To: "{To_mail}"')
    #     print(f'Subject: "{Subject}"')
    #     print(f'email body: \n {email_body}')
    #     print(f'Date: {datetime.datetime.now()}')
    #     print("================================================")
    #     signature = sign_email(private_key, email_body)
    #     print("\n✅ Digital signature created.")
    #     print("Digital Signature (Hex):")
    #     print(signature.hex())
    #     # print(f"Keys saved to 'KEYS/{user}_private_key.pem' and 'KEYS/{user}_public_key.pem'")
    # else:
    #     # check if user exists by finding the matched email addr
    #     print(f'✅✅ User \"{check_recipient}\" already exists. Using existing public key.')
    #     receiver_priv_key, receiver_pub_key = generate_or_load_keys(check_recipient, key_size)
    #     saved_keys(check_recipient,receiver_priv_key, receiver_pub_key)
    
    if check_recipient is not None:
        # if email not exists then create a new user with keys
        # then save the keys and just get going with the rest of the flow
        check_recipient = input("Enter the recipient's username: ")
        ex[check_recipient] = To_mail
        print(f'📥 Generating keys for new recipient: {check_recipient}')
        receiver_priv_key, receiver_pub_key = generate_or_load_keys(check_recipient, key_size)
        saved_keys(check_recipient,receiver_priv_key, receiver_pub_key)
    add_public_key_to_keyring(user, check_recipient)
    
    Subject = input("Enter the subject of the email: ")
    email_body = input("Enter the email body to sign: ")
    print("================================================")
    print(f'From: "{From}"')
    print(f'To: "{To_mail}"')
    print(f'Subject: "{Subject}"')
    print(f'email body: \n {email_body}')
    print(f'Date: {datetime.datetime.now()}')
    print("================================================")
    signature = sign_email(private_key, email_body)
    print("\n✅ Digital signature created.")
    print("Digital Signature (Hex):")
    print(signature.hex())


    # save the email and signature to a file
    print(f"Keys saved to 'KEYS/{user}_private_key.pem' and 'KEYS/{user}_public_key.pem'")
    with open("signed_email.txt", "w") as f:
        f.write(f"From: {From}\n")
        f.write(f"To: {To_mail}\n")
        f.write(f"Subject: {Subject}\n")
        f.write(f"Date: {datetime.datetime.now()}\n")
        f.write("Email Body:\n")
        f.write(email_body + "\n")
        f.write("Digital Signature (Hex):\n")
        f.write(signature.hex())

    print("📝 Email and signature saved to 'signed_email.txt'")

def receiver_flow():
    
    # handle not exists
    if not os.path.exists("KEYS"):
        print("❌ KEYS folder not found.")
        return
    
    if not os.path.exists("signed_email.txt"):
        print("❌ signed_email.txt not found.")
        return
    #old way manual input 
    # email_body = input("Enter the received email body: ")
    # signature_hex = input("Enter the received signature (hex): ")

    #new way to read from file
    with open("signed_email.txt", "r") as f:
        lines = f.readlines()

    # Extract values
    from_index = lines[0].split(": ")[1].strip()
    to_index = lines[1].split(": ")[1].strip()
    subject_index = lines[2].split(": ")[1].strip()
    date_index = lines[3].split(": ")[1].strip()
    email_body_index = lines.index("Email Body:\n") + 1
    signature_index = lines.index("Digital Signature (Hex):\n") + 1

    # Join email body lines until the signature section
    email_body = ''.join(lines[email_body_index:signature_index - 1])
    signature_hex = lines[signature_index].strip()
    
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        print("❌ Invalid signature format.")
        return
    #load the public key
    userID = None
    for user, email in ex.items():
        if email == from_index:
            userID = user
            print('✅user matched email: ', userID)
            break
    if userID is None:
        print("❌ User not found.")
        return
    senderID = userID.lower() #just in case
    sender_public_key = load_public_key(user,senderID)

    if sender_public_key is None:
        print(f"❌ You don't have {senderID }'s public key yet.")
        add_public_key_to_keyring(user, senderID)
        sender_public_key = load_public_key(user, senderID)
        if sender_public_key is None:
            print("❌ Unable to load sender's public key after attempt.")
            return



    #verify the signature
    if verify_signature(sender_public_key, email_body, signature):
        print("✅ Signature is VALID. The email is authentic.")
        print("================================================")
        print('📧THE EMAIL📧')
        print(f'From: {from_index}')
        print(f'To: {to_index}')
        print(f'Subject: {subject_index}')
        print(f'Date: {date_index}')
        print(f'email body: \n {email_body}')
        print("================================================")
        print('🔑 THE SIGNATURE🔑 ')
        print(f'signature: \n {signature.hex()}')
    else:
        print("❌ Signature is INVALID. The email may have been altered.")

def main():
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
