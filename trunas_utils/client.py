import os
from pathlib import Path
from truenas_api_client import Client


TRUENAS_HOST = os.environ.get('TRUENAS_HOSTNAME', None)
TRUENAS_APIKEY = os.environ.get('TRUENAS_API_KEY', None)
TRUENAS_PARENT_DATASET = os.environ.get('TRUENAS_PARENT_DATASET', None)
VERIFY_SSL = os.environ.get('TRUENAS_VERIFY_SSL', 'False').lower() in ['true', '1', 'yes']

STARFISH_HOSTS = os.environ.get('STARFISH_HOSTS', [])
GLOBUS_HOSTS = os.environ.get('GLOBUS_HOSTS', [])


class TrueNasClient:
    """
    A client to interact with the TrueNas API.
    This class provides methods to create datasets and NFS shares.
    It uses the TrueNas API to perform these operations.
    """
    def __init__(self, api_key=TRUENAS_APIKEY, hostname=TRUENAS_HOST, parent_dataset=TRUENAS_PARENT_DATASET, verify_ssl=VERIFY_SSL):
        if api_key is None:
            raise ValueError("API key is required to connect to TrueNas.")
        self.api_key = api_key
        self.uri = f"wss://{hostname}/websocket"
        self.parent_dataset = parent_dataset
        self.verify_ssl = verify_ssl

    def ping(self):
        """Ping the TrueNas server to check if the connection is alive."""
        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            if c.ping():
                print("Pinged TrueNas successfully")
                return True
            else:
                print("Cannot Ping TrueNas array")
                return False
    
    def set_default_acls(self, project_name):
        project_path = Path(f"/mnt/{self.parent_dataset}") / project_name

        self.__send_job("filesystem.setacl", {
                "path": project_path.as_posix(),  # Convert to POSIX path
                "dacl": self.generate_acls('770'),
                "acltype": "POSIX1E"
            })

    
    def generate_acls(self, unix_mode: str ='770'):
        """
        Generate the ACLs.
        The ACLs are generated based on the permissions provided.
        The permissions are a tuple of three booleans, each representing the
        permissions for the user, group, and other respectively.
        The permissions are in the order of READ, WRITE, EXECUTE.
        The default permissions are equivalent to unix permission mode 770.
        """
        def validate_mode(u_mode: str):
            # Check if the unix mode is a valid octal number
            if type(u_mode) != str or not u_mode.isdigit() or int(u_mode) < 0 or int(u_mode) > 777 or len(u_mode) != 3:
                raise ValueError("Invalid unix mode. Must be a 3 digit numeric string between 000 and 777.")
            elif int(u_mode[1]) > 7 or int(u_mode[2]) > 7:
                raise ValueError("Invalid unix mode. Must be a 3 digit numeric string with each digit between 0 and 7.")
            return True
        
        def generate_perm(tag, perm):
            # Convert the binary string to a list of booleans
            perm = format(int('0o' + perm, 8), '03b')
            perm = [bool(int(p)) for p in perm]
            return {
                "tag": tag,
                "perms": {"READ": perm[0], "WRITE": perm[1], "EXECUTE": perm[2]}
                }
        # Convert the unix mode to a binary string
        validate_mode(unix_mode)
        
        return [generate_perm("USER_OBJ", unix_mode[0]), 
                generate_perm("GROUP_OBJ", unix_mode[1]), 
                generate_perm("OTHER", unix_mode[2])]

    def get_acls(self, project_name):
        """
        Get the ACLs for a given project.
        """
        project_path = Path(f"/mnt/{self.parent_dataset}") / project_name

        #path, simplified, resolve_ids
        self.__send_arg_call("filesystem.getacl", project_path.as_posix(), True, False)
    
    def create_starfish_share(self, project_path: Path):
        return ("sharing.nfs.create", {
            "path": project_path.as_posix(),  # Convert to POSIX path
            "security": ['SYS'],
            "hosts": STARFISH_HOSTS,
            "maproot_user": 'root',
            "maproot_group": 'wheel',
            "comment": 'starfish',
            "ro": True
        })
    
    def create_globus_share(self, project_path: Path):
        return ("sharing.nfs.create", {
            "path": project_path.as_posix(),  # Convert to POSIX path
            "security": ['SYS'],
            "hosts": GLOBUS_HOSTS,
            "comment": 'globus'
        })
    
    def create_project_share(self, project_name: str, quota: int, owner_uid: int, owning_group_gid: int):
        """
        Create a dataset and NFS share for an RT project.
        # Create dataset with quota
        # Create the NFS Share for starfish, RO, no_root_squash
        # Create the NFS Share for globus DTNs
        # Set owners (chown)
        # Set permissions (chmod)
        """
        project_path = Path(f"/mnt/{self.parent_dataset}") / project_name
        self.__send_calls([
            ("pool.dataset.create", {
                "name": f"{self.parent_dataset}/{project_name}",
                "type": "FILESYSTEM", #VOLUME OR FILESYSTEM
                "acltype": "POSIX",
                "refquota": quota
            }),
            self.create_starfish_share(project_path),
            self.create_globus_share(project_path)
        ])  # Send the commands to TrueNas

        self.__send_job("filesystem.chown", {
            "path": project_path.as_posix(),
            "uid": owner_uid,
            "gid": owning_group_gid
        })
        self.__send_job("filesystem.setacl", {
                "path": project_path.as_posix(),
                "dacl": [
                    {"tag": "user", "id": owner_uid, "permissions": "full"},
                    {"tag": "group", "id": owning_group_gid, "permissions": "full"},
                    {"tag": "other", "permissions": "none"}
                ],
                "acltype": "POSIX1E"
        })
        print(f"Created Tier2 dataset and share {project_name} with quota {quota} for owner UID {owner_uid} and GID {owning_group_gid}.")
        """
            #interesting methods
            #filesystem.can_access_as_user
            #filesystem.mkdir
            #filesystem.acl_is_trivial

            #sharing.nfs.delete   takes    id
            #sharing.nfs.get_instance  takes    id
            #sharing.nfs.query      takes query-filters
            #sharing.nfs.update
        """
    def __send_arg_call(self, command: str, *args):
        """
        Send a single command to TrueNas with the provided arguments.
        """
        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            c.call("auth.login", {
                "api_key": self.api_key
            })
            c.ping()
            print(f"Sending command: {command} with args: {args}")
            c.call(command, *args)

    def __send_calls(self, commands: list[tuple[str, dict]]):

        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            c.call("auth.login", {
                "api_key": self.api_key
            })
            c.ping()
            for command, payload in commands:
                # Send the command to TrueNas
                print(f"Sending command: {command} with payload: {payload}")           
                c.call(command, payload)

    def __send_job(self, command: str, payload: dict):

        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            c.call("auth.login", {
                "api_key": self.api_key
            })
            c.ping()
            print(f"Sending job: {command} with payload: {payload}")           
            c.call(command, payload, job=True)

