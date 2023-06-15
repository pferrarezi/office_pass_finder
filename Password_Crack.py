import itertools
import msoffcrypto
import string
import subprocess


def main():  # main function to select function
    print("Funciona com senhas numéricas de até 10 números de 0 a 9 de tamanho.")
    print("Escolha a extensão:")
    which = int(input(
        "1 = .docx/.xlsx, 2 = PGP\n"
        "Stop! : "))
    if which == 1:
        try:
            file_docx = str(input("Which DOCX/XLSX-File?\n"))
            decrypt_docx(file_docx)
        except:
            print("Error!")
    elif which == 2:
        try:
            file_gpg = str(input("Which File?\n"))
            decrypt_gpg(file_gpg)
        except:
            print("Error!")
    else:
        print("not implemented yet")  # if you're stupid :D
    input("Press any key to continue...")


def decrypt_docx(file_docx):
    chars = string.digits
    attempts = 0
    # print that you can go shopping :D
    print("Lançando ataques no arquivo docx/xlsx!\nIsso pode demorar...")
    for plen in range(1, 11):  # already the same
        for guess in itertools.product(chars, repeat=plen):
            attempts += 1
            guess = ''.join(guess)
            print(f"Atque: {guess}", end='\r')
            # print(guess,attempts)                                          #Debug
            try:
                # try start msoffcrypto-tool as OfficeFile with
                file = msoffcrypto.OfficeFile(open(file_docx, "rb"))
                # file-name and read-access only
                # if password required, take the generated
                file.load_key(password=guess)
                file.decrypt(open("decrypted.docx",
                                  "wb"))  # if password correct, open new file with write-access and copy content in it
                print(
                    "[DOCX, XLSX BRUTE-FORCE]: found password! password: {} with {} attempts".format(guess, attempts))
                return True
            except:
                # print(str(attempts)+"not correct!")                        #Debug
                continue  # otherwise continue with next password


def decrypt_gpg(file_gpg):
    chars = string.ascii_letters + string.digits
    attempts = 0
    # print that you can go shopping :D
    print("Searching for password!\nThis may take long time...")
    for plen in range(1, 11):  # already the same
        for guess in itertools.product(chars, repeat=plen):
            attempts += 1
            guess = ''.join(guess)
            # print(guess,attempts)                                          #Debug
            try:
                # try get true by using function checkPassword which use the file
                if checkPassword(file_gpg, guess):
                    # as file_gpg and generated password
                    print("[GPG BRUTE-FORCE]: found password! "
                          "password: {} with {} attempts".format(guess, attempts))  # print success!
                    return True
            except:
                # print(str(attempts)+" not correct!")                       #Debug
                continue  # otherwise next password


# function to check password from gpg-encrypted files
def checkPassword(filename, password):
    output = ""
    try:  # try create new subprocess with check_output function. Execute command at shell.
        # gpg = start gpg, --pinentry-mode loopback = send a password directly to GnuPG,
        # rather than GnuPG itself prompting for the password.
        # --output decrypted_gpg.txt = after decryption save it decrypted in txt-file
        # --batch --yes = execute int batch true
        # --passphrase password = generated password from function decrypt_gpg()
        # -d filename = encrypted file to decrypt
        # shell = True --> open in shell
        subprocess.check_output(
            "gpg --pinentry-mode loopback --output decrypted_gpg.txt --batch --yes --passphrase " + password +
            " -d " + filename + " 2>&1", shell=True)
        return True  # if executed without errors return True and password was correct
    except subprocess.CalledProcessError as e:  # if subprocess-error you can print it out
        # out = str(e.output)                                                #Debug
        # print(out)                                                         #Debug
        return False  # password wasn´t correct
    except:
        return False  # if other error return False --> next password


if __name__ == "__main__":  # declare function main() as first executed function
    main()
