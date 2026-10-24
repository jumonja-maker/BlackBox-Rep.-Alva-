"""Delete only a native-identity-checked entry, never recurse through a link.
Windows uses OPEN_REPARSE_POINT, GetFileInformationByHandle,
GetFinalPathNameByHandleW and SetFileInformationByHandle(FileDispositionInfo).
POSIX anchors traversal with directory file descriptors and O_NOFOLLOW.
"""
import ctypes as C,os,stat
from pathlib import Path
from .library_files import checked
class WindowsFile:
 def __init__(self,path,*,delete=False):
  from ctypes import wintypes as W
  k=self.k=C.WinDLL('kernel32',use_last_error=True)
  class Info(C.Structure):
   _fields_=[('attributes',W.DWORD),('created',W.FILETIME),('accessed',W.FILETIME),('written',W.FILETIME),('volume',W.DWORD),('size_high',W.DWORD),('size_low',W.DWORD),('links',W.DWORD),('index_high',W.DWORD),('index_low',W.DWORD)]
  k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE];k.CreateFileW.restype=W.HANDLE
  k.GetFileInformationByHandle.argtypes=[W.HANDLE,C.POINTER(Info)];k.GetFileInformationByHandle.restype=W.BOOL
  k.GetFinalPathNameByHandleW.argtypes=[W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD];k.GetFinalPathNameByHandleW.restype=W.DWORD
  k.SetFileInformationByHandle.argtypes=[W.HANDLE,C.c_int,C.c_void_p,W.DWORD];k.SetFileInformationByHandle.restype=W.BOOL
  k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
  self.handle=k.CreateFileW(str(path),0x80|(0x10000 if delete else 0),7,None,3,0x02000000|0x00200000,None)
  if self.handle in (None,C.c_void_p(-1).value):raise OSError(C.get_last_error(),'OWNED_DELETE_OPEN_FAILED')
  try:
   info=Info()
   if not k.GetFileInformationByHandle(self.handle,C.byref(info)):raise OSError(C.get_last_error(),'OWNED_DELETE_ID_FAILED')
   if info.attributes&0x400:raise ValueError('OWNED_DELETE_REPARSE_POINT')
   buffer=C.create_unicode_buffer(32768);n=k.GetFinalPathNameByHandleW(self.handle,buffer,len(buffer),0)
   if not 0<n<len(buffer):raise OSError(C.get_last_error(),'OWNED_DELETE_FINAL_PATH_FAILED')
   final=buffer.value
   if final.startswith('\\\\?\\UNC\\'):raise ValueError('OWNED_DELETE_UNC')
   if final.startswith('\\\\?\\'):final=final[4:]
   self.final=os.path.normcase(os.path.normpath(final));self.identity=['WIN32_FILE_ID',int(info.volume),int(info.index_high)<<32|int(info.index_low)];self.directory=bool(info.attributes&0x10)
  except BaseException:self.close();raise
 def close(self):
  if self.handle is not None:self.k.CloseHandle(self.handle);self.handle=None
 def remove(self):
  flag=C.c_ubyte(1) # FILE_DISPOSITION_INFO contains one BOOLEAN.
  if not self.k.SetFileInformationByHandle(self.handle,4,C.byref(flag),C.sizeof(flag)):raise OSError(C.get_last_error(),'OWNED_DELETE_DISPOSITION_FAILED')
def file_identity(path):
 path=checked(path)
 if os.name=='nt':
  f=WindowsFile(path)
  try:return {'identity':f.identity,'final_path':f.final,'directory':f.directory}
  finally:f.close()
 st=path.lstat()
 if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):raise ValueError('OWNED_DELETE_FILE_TYPE')
 return {'identity':['POSIX_INODE',st.st_dev,st.st_ino],'final_path':str(path),'directory':stat.S_ISDIR(st.st_mode)}
def remove_entry(root,relative,expected,root_expected):
 root=checked(root);parts=Path(relative).parts
 if relative!='.' and (not parts or Path(relative).is_absolute() or any(p in ('.','..') for p in parts)):raise ValueError('OWNED_DELETE_RELATIVE_PATH')
 path=root if relative=='.' else checked(root.joinpath(*parts))
 if file_identity(root)['identity']!=root_expected['identity']:raise ValueError('OWNED_DELETE_ROOT_CHANGED')
 if os.name=='nt':
  f=WindowsFile(path,delete=True)
  try:
   final=os.path.normcase(os.path.normpath(str(Path(root_expected['final_path']).joinpath(*(() if relative=='.' else parts)))))
   if f.identity!=expected['identity'] or f.directory!=expected['directory'] or f.final!=final:raise ValueError('OWNED_DELETE_ENTRY_CHANGED')
   f.remove()
  finally:f.close()
 elif os.name=='posix':
  anchor=root.parent if relative=='.' else root;names=(root.name,) if relative=='.' else parts;fds=[]
  try:
   fd=os.open(anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
   if relative!='.':
    st=os.fstat(fd)
    if ['POSIX_INODE',st.st_dev,st.st_ino]!=root_expected['identity']:raise ValueError('OWNED_DELETE_ROOT_CHANGED')
   for part in names[:-1]:
    fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
   st=os.stat(names[-1],dir_fd=fd,follow_symlinks=False)
   if ['POSIX_INODE',st.st_dev,st.st_ino]!=expected['identity'] or stat.S_ISDIR(st.st_mode)!=expected['directory']:raise ValueError('OWNED_DELETE_ENTRY_CHANGED')
   if expected['directory']:os.rmdir(names[-1],dir_fd=fd)
   elif stat.S_ISREG(st.st_mode):os.unlink(names[-1],dir_fd=fd)
   else:raise ValueError('OWNED_DELETE_FILE_TYPE')
  finally:
   for fd in reversed(fds):os.close(fd)
 else:raise OSError('OWNED_DELETE_PLATFORM_UNSUPPORTED')
 if path.exists():raise OSError('OWNED_DELETE_COMPLETION_UNCONFIRMED')

