import sys
import shutil
import os
import hashlib
import errno

if 'KURASUTA_STORAGE' not in os.environ:
    raise Exception('environment variable KURASUTA_STORAGE missing')

kurasuta_storage = os.environ['KURASUTA_STORAGE']
if not os.path.exists(kurasuta_storage):
    raise Exception('KURASUTA_STORAGE location "%s" missing' % kurasuta_storage)
if not os.path.isdir(kurasuta_storage):
    raise Exception('KURASUTA_STORAGE location "%s" is not a directory' % kurasuta_storage)


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


for file_name in sys.argv[1:]:
    with open(file_name) as fp:
        content = fp.read()
        fp.close()
    sha256 = hashlib.sha256(content).hexdigest()

    target_folder = os.path.join(kurasuta_storage, sha256[0], sha256[1], sha256[2])
    mkdir_p(target_folder)
    shutil.move(file_name, os.path.join(target_folder, sha256))
