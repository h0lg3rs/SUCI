# Home.py. Vi skal utføre deconceal som 

from SUCI_util import *
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PRIVPW   = bytes("BTS4410 Høsten 2025","utf-8")

cmd = cmd_arg([CMD_KEYGEN,CMD_DECONCEAL]) #her brukes keygen og deconceal som commands.

if cmd==None:
    err_print("\nNo valid command given.")
    sys.exit(1)


if cmd==CMD_KEYGEN:
    print("\nHome: Generating long-term ECDH key-pair.")
    private_key, public_key = gen_ECDH_key_pair(ec.SECP256R1())
    
    print("    Key-pair generated.")
    
    len_priv_pem = len(store_private_key(private_key,PRIV_PEM,PRIVPW))
    print("    Private key stored in pem-file. Filesize:",len_priv_pem)
    
    len_pub_pem = len(store_public_key(public_key,PUB_PEM))
    print("    Public key stored in pem-file.  Filesize:",len_pub_pem)    
    
    print("Home: Command completed.")
    sys.exit(0)
    

if cmd==CMD_DECONCEAL:
    print("\nHome: Deconceal command given.")
    
    priv_key = load_private_key(PRIV_PEM, PRIVPW)
    print("    Loaded own private key. Size:",priv_key.key_size)
    
    f = open(SUCI_FILE_NAME,"rb")
    raw_suci_data = f.read()
    f.close()
    print("    Loaded: "+SUCI_FILE_NAME+", Length:",len(raw_suci_data))
    
   
    IV = raw_suci_data[0:16]
    len_home_ID = int.from_bytes(raw_suci_data[16:18])
    home_ID_arr = 18 + len_home_ID
    home_ID = raw_suci_data[18:home_ID_arr]
    pubkey_len = int.from_bytes(raw_suci_data[80:82])
    pubkey_arr = 82 + pubkey_len
    pubkey = raw_suci_data[82:pubkey_arr]
    ct_found = raw_suci_data[pubkey_arr:]
    
    # Laster inn Home Public key.
    home_pub_key = load_public_key(PUB_PEM)
        
    # henter public key fra binær filen
    ephemeral_public_key = serialization.load_pem_public_key(pubkey)
        
    # genererer hemmeligheten med bruk av egen private og tilsendt public
    dhs = priv_key.exchange(ec.ECDH(),ephemeral_public_key)
        
    # generer session key
    session_key = key_derivation(dhs)
    
    # dekrypterer binærfilen med session key
    aesgcm = AESGCM(session_key)
    aad = IV + raw_suci_data[16:80] + raw_suci_data[80:pubkey_arr]
    ct = aesgcm.decrypt(IV, ct_found, aad)
    
    len_ct = int.from_bytes(ct[0:2])
    user_ID_arr = 2 + len_ct
    user_ID = ct[2:user_ID_arr]

    #printer ut informasjon vi har funnet
    print("IV len:", len(IV))
    print("Home ID len:", len_home_ID)
    print("Public key len:", pubkey_len)
    print("Entity name home:", home_ID.decode("utf-8"))
    print("Public key:\n", pubkey.decode("utf-8"))
    print(f"Ciphertext length:{len(ct_found)} (includes the tag)")
    print("The de-concealed user entity name:", user_ID.decode("utf-8"))

    print("Home: Command completed.")    
    sys.exit(0)


err_print("\nSomething went wrong:",cmd)
sys.exit(1)