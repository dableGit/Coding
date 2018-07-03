import os
import hashlib
import win32security
import pywintypes
from operator import attrgetter


SEARCHFOLDER = 'F:\\Coding'
TRESHOLD = 100
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


def csv_line(file_info):
    ret = file_info.hash + CSV_SEP + file_size_MB(file_info.size) + \
        CSV_SEP + file_info.folder + \
        CSV_SEP + file_info.filename + \
        CSV_SEP + file_info.owner + '\n'
    return ret


def write_csv(file_infos):
    outfile = open(SEARCHFOLDER + '\\out.csv', 'w')

    # Sort list by hash
    # sorted_file_infos = sorted(
    # file_infos, key=itemgetter('file_infos'), reverse=True)

    # Write Header
    outfile.write('Hash; Size; Folder; Filename; Owner\n')

    # Write line per entry, depending on duplicate or not
    for file_info in file_infos:
        if file_info.size > TRESHOLD:
            outfile.write(csv_line(file_info))

    outfile.close()


def get_file_infos_list():
    file_infos = []
    for folderName, _subfolders, filenames in os.walk(SEARCHFOLDER):
        for filename in filenames:
            file_info = FileInfo(folderName, filename)
            file_infos.append(file_info)
    file_infos.sort(reverse=True)
    return file_infos


class FileInfo():
    # hash_dict = {}

    def __init__(self, folder, filename):
        self.folder = folder
        self.filename = filename
        self.fullpath = os.path.join(folder, filename)
        # FileInfo.hash_dict[hashfile(self.fullpath)].append(self)
        self.hash = hashfile(self.fullpath)
        self.size = os.path.getsize(self.fullpath)
        self.owner = get_owner(self.fullpath)

    def __lt__(self, other):
        return self.size < other.size


if __name__ == "__main__":
    file_infos = get_file_infos_list()
    write_csv(file_infos)
