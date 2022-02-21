# orc-decrypt.py : Tools for decrypting DFIR-ORC archives

DFIR-Orc can encrypt its archives with PKCS7. Decryption can be achieved with the help of OpenSSL with the `cms` 
subcommand. However, OpenSSL has a bug which prevents it from decrypting archives larger than 2 GB. Thus a (slower) Python
implementation has been written in order to address this issue.

Once the PKCS7 envelope has been decrypted, the output is not yet a valid 7z archive. Therefore a second tool, `unstream`, 
needs to be run in order to produce the final 7z archive. 

orc-decrypt.py is the wrapper around both decryption implementations and for the `unstream` command.

## Requirements
- Python 3.6+
- [PyCryptodome](https://www.pycryptodome.org/en/latest/)
- OpenSSL command line tool in the PATH
- Compiled `unstream` from this repository in the same directory as `orc-decrypt.py`. Use either the `Makefile` (make) or `CMakeLists.txt` (CMake).

## Usage
```
usage: orc-decrypt.py [-h] -k file [--log-level level] [--log-file file] [-f] [-j N] [-m mode] input_dir output_dir

Wrapper around the two possible methods of decrypting ORC archives

positional arguments:
  input_dir             Input directory where the encrypted archives are stored
  output_dir            Output directory where to store the decrypted archives

optional arguments:
  -h, --help            show this help message and exit
  -k file, --key file   PEM-encoded unencrypted key file (default: None)
  --log-level level     Print log messages of this level and higher, possible choices: CRITICAL, ERROR, WARNING, INFO, DEBUG (default: INFO)
  --log-file file       Log file to store DEBUG level messages (default: None)
  -f, --force           Force overwrite of existing files in output directory. (default: False)
  -j N, --jobs N        Number of jobs to process in parallel. Defaults to Python implementation of multiprocessing.Pool (default: None)
  -m mode, --method mode
                        Method to use to decrypt archives. Default is 'auto' meaning the script will use openssl for archives smaller than 2GB and pure-python implementation for larger ones. Warning: forcing the usage of openssl for
                        archives larger than 2GB will likely prevent the script from decrypting these archives as openssl cannot handle them in its current version (1.1.1f) (default: auto)
```

## Examples
```bash
$ ls ./encrypted
ORC_Server_server1.example.com_Main.7z.p7b ORC_Server_server1.example.com_Hives.7z.p7b
$ cat key.pem
-----BEGIN PRIVATE KEY-----
[...]
-----END PRIVATE KEY-----
$ python orc-decrypt.py -k key.pem ./encrypted ./decrypted
```

## CMake build instructions (Windows/Linux)
```
cd orc-decrypt
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## License
Le contenu de ce dépôt est disponible sous licence LGPL2.1+, tel qu'indiqué [ici](LICENSE.txt)

Le nom DFIR ORC et le logo associé appartiennent à l'ANSSI, aucun usage n'est permis sans autorisation expresse.

The contents of this repository is available under [LGPL2.1+](LICENSE.txt). 

The name DFIR ORC and the associate logo belongs to ANSSI, no use is permitted without its express approval.
