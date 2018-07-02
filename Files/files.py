import os
import hashlib
import win32security
import pywintypes
from operator import itemgetter


SEARCHFOLDER = 'F:\\Coding'
TRESHOLD = 10000
CSV_SEP = ';'


def hashfile(path, blocksize=65536):
    afile = open(path, 'rb')
    hasher = hashlib.md5()
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    afile.close()
    return hasher.hexdigest()


def file_size(size):
    if size < 1024:
        return str(size) + ' Bytes'
    else:
        size = size / 1024
        if size < 1024:
            return '{:.2f}'.format(size) + ' MB'
        else:
            size = size / 1024
            return '{:.2f}'.format(size) + ' GB'


def file_size_MB(size):
    return '{:.2f}'.format(size / (1024*1024)).replace('.', ',')


def get_owner(file):
    sd = win32security.GetFileSecurity(
        file, win32security.OWNER_SECURITY_INFORMATION)
    owner_sid = sd.GetSecurityDescriptorOwner()
    try:
        name, _domain, _type = win32security.LookupAccountSid(None, owner_sid)
        return name
    except pywintypes.error:  # pylint:disable=E1101
        return 'unknown'


def csv_line(file):
    ret = file['hash'] + CSV_SEP + file_size_MB(file['wasted_size']) + \
        CSV_SEP + file_size_MB(file['size']) + \
        CSV_SEP + file['owner'] + CSV_SEP
    for path in file['paths']:
        ret += path + CSV_SEP
    ret += '\n'
    return ret


def write_csv(file_list, duplicates_only=True):
    outfile = open(SEARCHFOLDER + '\\out.csv', 'w')

    # Sort list by wasted size
    sorted_file_list = sorted(
        file_list, key=itemgetter('wasted_size'), reverse=True)

    # Write Header
    outfile.write('Hash; Wasted Size; Size; Owner; Paths\n')

    # Write line per entry, depending on duplicate or not
    for file in sorted_file_list:
        if file['wasted_size'] < TRESHOLD:
            continue
        if duplicates_only:
            if file['duplicate']:
                outfile.write(csv_line(file))
        else:
            outfile.write(csv_line(file))

    outfile.close()


def get_file_list():
    file_list = []
    for folderName, _subfolders, filenames in os.walk(SEARCHFOLDER):
        for filename in filenames:
            duplicate = False
            fullpath = os.path.join(folderName, filename)
            hash_md5 = hashfile(fullpath)
            for file in file_list:
                if file['hash'] == hash_md5:
                    duplicate = True
                    # print(file[hash_md5])
                    file['duplicate'] = duplicate
                    file['paths'].append(fullpath)
                    file['wasted_size'] = file['size'] * \
                        (len(file['paths']) - 1)

            if duplicate is False:
                hash_dict = {'hash': hash_md5,
                             'size': os.path.getsize(fullpath),
                             'owner': get_owner(fullpath),
                             'duplicate': duplicate,
                             'paths': [fullpath, ],
                             'wasted_size': 0}

                file_list.append(hash_dict)
    return file_list


if __name__ == "__main__":
    file_list = get_file_list()
    write_csv(file_list)
