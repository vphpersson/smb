# smb

Work in progress!

## Example applications

### Enumerate files in a share and note the path of each bat script

```python
#!/usr/bin/env python3

from asyncio import run as asyncio_run, gather as asyncio_gather
from typing import List, Union, Callable, Optional
from pathlib import PureWindowsPath
from sys import stderr

from msdsalgs.fscc.file_information import FileInformation

from smb.transport import TCPIPTransport
from smb.v2.connection import Connection as SMBv2Connection
from smb.v2.session import Session
from smb.v2.messages.query_directory import FileInformationClass, FileDirectoryInformation, QueryDirectoryFlag


async def enumerate_share_files(
    smb_session: Session,
    tree_id: int,
    root_path: Union[str, PureWindowsPath] = '',
    num_max_concurrent: int = 10,
    per_file_callback: Optional[Callable[[PureWindowsPath, FileInformation, Session, int], bool]] = None
) -> None:
    """
    Enumerate files in an SMB share.

    By default, the the share is enumerated from its root and all descendant directories are enumerated recursively. The
    `per_file_callback` allows one to inspect each enumerated file as they are encountered and -- in the case of
    directories -- make a decision whether to enumerate it.

    :param smb_session: An SMB session with access to the share whose files are to be enumerated.
    :param tree_id: The tree id of the share whose files are to be enumerated.
    :param root_path: The root path from which to enumerate files.
    :param num_max_concurrent: The maximum number of concurrent tasks.
    :param per_file_callback: A callback function that inspects paths and determines whether to enumerate them.
    :return: None
    """

    async def scan_directory(path: PureWindowsPath) -> List[FileDirectoryInformation]:
        """
        Scan a directory in an SMB share and provide information about its contents.

        :param path: The path of the directory to be scanned.
        :return: A list of the path's file and directory information entries.
        """

        async with smb_session.create_dir(path=path, tree_id=tree_id) as create_response:
            return await smb_session.query_directory(
                file_id=create_response.file_id,
                file_information_class=FileInformationClass.FileIdFullDirectoryInformation,
                query_directory_flag=QueryDirectoryFlag(),
                file_name_pattern='*',
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

    paths_to_scan: List[Union[PureWindowsPath, str]] = [root_path]

    while paths_to_scan:
        num_remaining_paths = len(paths_to_scan)
        paths_to_scan_in_iteration = [paths_to_scan.pop() for _ in range(min(num_remaining_paths, num_max_concurrent))]
        scan_results: List[Union[List[FileDirectoryInformation], Exception]] = await asyncio_gather(
            *[scan_directory(path) for path in paths_to_scan_in_iteration],
            return_exceptions=True
        )

        for directory_path, scan_result in zip(paths_to_scan_in_iteration, scan_results):
            if isinstance(scan_result, Exception):
                # print(f'{directory_path}: {scan_result}', file=stderr)
                continue

            file_directory_information_list: List[FileDirectoryInformation] = scan_result
            for entry in file_directory_information_list:
                if entry.file_name in {'.', '..'}:
                    continue

                entry_path: PureWindowsPath = PureWindowsPath(directory_path) / entry.file_name
                should_scan: bool = per_file_callback(
                    entry_path,
                    entry.file_information,
                    smb_session,
                    tree_id
                )

                if entry.file_information.file_attributes.directory and should_scan:
                    paths_to_scan.append(entry_path)


async def main():

    address = '192.168.56.101'
    port_number = 445
    username = 'vph'
    password = 'PASSWORD'
    share_name = 'Users'

    async with TCPIPTransport(address=address, port_number=port_number) as tcp_ip_transport:
        async with SMBv2Connection(tcp_ip_transport=tcp_ip_transport) as smb_connection:
            await smb_connection.negotiate()
            async with smb_connection.setup_session(username=username, authentication_secret=password) as smb_session:
                async with smb_session.tree_connect(share_name=share_name) as (tree_id, _):
                    script_paths: List[str] = []

                    def collect_script_paths(entry_path: PureWindowsPath, *_, **__) -> bool:
                        if entry_path.suffix.lower() == '.bat':
                            script_paths.append(str(entry_path))
                        return True

                    await enumerate_share_files(
                        smb_session=smb_session,
                        tree_id=tree_id,
                        per_file_callback=collect_script_paths
                    )

                    print('\n'.join(script_paths))


if __name__ == '__main__':
    asyncio_run(main())
```

**Output:**
```
vph\AppData\Local\Programs\Python\Python38-32\Lib\venv\scripts\nt\activate.bat
vph\AppData\Local\Programs\Python\Python38-32\Lib\venv\scripts\nt\deactivate.bat
vph\AppData\Local\Programs\Python\Python38-32\Lib\idlelib\idle.bat
vph\AppData\Local\Programs\Python\Python38-32\Lib\ctypes\macholib\fetch_macholib.bat
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

### Enumerate shares on a host (with the help of my [rpc](https://github.com/vphpersson/rpc) and [ms_srvs](https://github.com/vphpersson/ms_srvs) libraries!)

```python
# #!/usr/bin/env python3
from asyncio import run as asyncio_run

from smb.transport import TCPIPTransport
from smb.v2.connection import Connection as SMBv2Connection
from rpc.connection import Connection as RPCConnection
from rpc.structures.context_list import ContextList, ContextElement
from ms_srvs import MS_SRVS_ABSTRACT_SYNTAX, MS_SRVS_PIPE_NAME
from ms_srvs.operations.netr_share_enum import netr_share_enum, NetrShareEnumRequest
from ms_srvs.structures.share_info_container import ShareInfo1Container


async def main():
    address = '192.168.56.101'
    port_number = 445
    username = 'vph'
    password = 'PASSWORD'

    async with TCPIPTransport(address=address, port_number=port_number) as tcp_ip_transport:
        async with SMBv2Connection(tcp_ip_transport=tcp_ip_transport) as smb_connection:
            await smb_connection.negotiate()
            async with smb_connection.setup_session(username=username, authentication_secret=password) as smb_session:
                async with smb_session.make_smbv2_transport(pipe=MS_SRVS_PIPE_NAME) as (r, w):
                    async with RPCConnection(reader=r, writer=w) as rpc_connection:
                        await rpc_connection.bind(
                            presentation_context_list=ContextList([
                                ContextElement(context_id=0, abstract_syntax=MS_SRVS_ABSTRACT_SYNTAX)
                            ])
                        )

                        share_info_container = (
                            await netr_share_enum(
                                rpc_connection=rpc_connection,
                                request=NetrShareEnumRequest(level=1)
                            )
                        ).info_struct.share_info

                        if not isinstance(share_info_container, ShareInfo1Container):
                            raise ValueError('Bad share info container type.')

                        print(
                            '\n\n'.join([
                                f'Name: {entry.netname}\n'
                                f'Type: {entry.share_type}\n'
                                f'Remark: {entry.remark}'
                                for entry in share_info_container.entries
                            ])
                        )


if __name__ == '__main__':
    asyncio_run(main())
```

**Output:**
```
Name: ADMIN$
Type: Disk drive (special)
Remark: Remote Admin

Name: C$
Type: Disk drive (special)
Remark: Default share

Name: cool_share
Type: Disk drive 
Remark: 

Name: IPC$
Type: Interprocess communication (special)
Remark: Remote IPC

Name: Users
Type: Disk drive
Remark:
```

:thumbsup:
