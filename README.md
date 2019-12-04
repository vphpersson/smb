# smb

Work in progress!

## Example application

### Enumerate files in a share and note the path of each bat script

```python
#!/usr/bin/env python3
from asyncio import run as asyncio_run, gather as asyncio_gather
from typing import List, Coroutine, Union, Tuple, Callable, Optional
from pathlib import PureWindowsPath

from smb.v2.connection import SMBv2Connection
from smb.v2.session import SMBv2Session
from smb.v2.messages.query_directory.query_directory_request import FileInformationClass, QueryDirectoryFlag
from smb.v2.messages.query_directory.query_directory_response import FileDirectoryInformation, FileInformation


async def enumerate_share_files(
    smb_connection: SMBv2Connection,
    smb_session: SMBv2Session,
    tree_id: int,
    root_path: Union[str, PureWindowsPath] = '',
    num_max_concurrent: int = 10,
    per_file_callback: Optional[
        Callable[[PureWindowsPath, FileInformation, SMBv2Connection, SMBv2Session, int], bool]
    ] = None
) -> None:
    """
    Enumerate files in an SMB share.

    By default, the the share is enumerated from its root and all descendant directories are enumerated recursively. The
    `per_file_callback` allows one to inspect each enumerated file as they are encountered and -- in the case of
    directories -- make a decision whether to enumerate it.

    :param smb_connection: An SMB connection with access to the share whose files are to be enumerated.
    :param smb_session: An SMB session with access to the share whose files are to be enumerated.
    :param tree_id: The tree id of the share whose files are to be enumerated.
    :param root_path: The root path from which to enumerate files.
    :param num_max_concurrent: The maximum number of concurrent tasks.
    :param per_file_callback: A callback function that inspects paths and determines whether to enumerate them.
    :return: None
    """

    async def scan_directory(path: PureWindowsPath) -> Tuple[PureWindowsPath, List[FileDirectoryInformation]]:
        """
        Scan a directory in an SMB share and provide information about its contents.

        :param path: The path of the directory to be scanned.
        :return: The path of the enumerated directory and a list of its file/directory information entries.
        """

        async with smb_connection.create_dir(path=path, session=smb_session, tree_id=tree_id) as create_response:
            return PureWindowsPath(path), await smb_connection.query_directory(
                file_id=create_response.file_id,
                file_information_class=FileInformationClass.FileIdFullDirectoryInformation,
                query_directory_flag=QueryDirectoryFlag(),
                file_name_pattern='*',
                session=smb_session,
                tree_id=tree_id
            )

    def default_per_file_callback(entry_path: PureWindowsPath, *_) -> bool:
        """
        Print each encountered file's path and decide to enumerate an encountered directory.
        
        :param entry_path: The path of an encountered file in an SMB share.
        :return: Whether to enumerate an encountered directory. Always `True`.
        """
        print(entry_path)
        return True

    per_file_callback = per_file_callback or default_per_file_callback

    scan_directory_coroutines: List[Coroutine[None, None, Tuple[PureWindowsPath, List[FileDirectoryInformation]]]] = [
        scan_directory(path=root_path)
    ]

    while scan_directory_coroutines:
        num_remaining_coroutines = len(scan_directory_coroutines)

        result_pairs: List[Tuple[Union[str, PureWindowsPath], List[FileDirectoryInformation]]] = await asyncio_gather(
            *[
                scan_directory_coroutines.pop()
                for _ in range(min(num_remaining_coroutines, num_max_concurrent))
            ]
        )

        for directory_path, file_directory_information_list in result_pairs:
            for entry in file_directory_information_list:
                if entry.file_name in {'.', '..'}:
                    continue

                entry_path: PureWindowsPath = directory_path / entry.file_name
                should_scan: bool = per_file_callback(
                    entry_path,
                    entry.file_information,
                    smb_connection,
                    smb_session,
                    tree_id
                )

                if not entry.file_information.file_attributes.directory:
                    continue

                if should_scan:
                    scan_directory_coroutines.append(scan_directory(path=entry_path))


async def main():
    async with SMBv2Connection(host_address='192.168.4.13') as smb_connection:
        await smb_connection.negotiate()
        async with smb_connection.setup_session(username='vph', authentication_secret='PASSWORD') as smb_session:
            async with smb_connection.tree_connect(share_name='Users', session=smb_session) as (tree_id, share_type):
                script_paths: List[PureWindowsPath] = []

                def collect_script_paths(entry_path: PureWindowsPath, *_, **__) -> bool:
                    if entry_path.suffix.lower() == '.bat':
                        script_paths.append(entry_path)
                    return True

                await enumerate_share_files(
                    smb_connection=smb_connection,
                    smb_session=smb_session,
                    tree_id=tree_id,
                    per_file_callback=collect_script_paths
                )

                print('\n'.join(str(script_path) for script_path in script_paths))


if __name__ == '__main__':
    asyncio_run(main())
```

**Output:**
```
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\ghidraRun.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\analyzeHeadless.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\buildGhidraJar.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\convertStorage.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\createPdbXmlFiles.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\dumpGhidraThreads.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\ghidraDebug.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\launch.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\pythonRun.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\support\sleigh.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\server\ghidraSvr.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\server\svrAdmin.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\server\svrInstall.bat
vph\Downloads\ghidra_9.0.4_PUBLIC_20190516\ghidra_9.0.4\server\svrUninstall.bat
```

:thumbsup:
