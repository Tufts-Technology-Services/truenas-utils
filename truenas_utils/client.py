import os
from pathlib import Path
from truenas_api_client import Client


TRUENAS_HOST = os.environ.get('TRUENAS_HOSTNAME', None)
TRUENAS_APIKEY = os.environ.get('TRUENAS_API_KEY', None)
TRUENAS_PARENT_DATASET = os.environ.get('TRUENAS_PARENT_DATASET', None)
VERIFY_SSL = os.environ.get('TRUENAS_VERIFY_SSL', 'False').lower() in ['true', '1', 'yes']

STARFISH_HOSTS = os.environ.get('STARFISH_HOSTS', [])
GLOBUS_HOSTS = os.environ.get('GLOBUS_HOSTS', [])


class TrueNASClient:
    """
    A client to interact with the TrueNas API.
    This class provides methods to create datasets and NFS shares.
    It uses the TrueNas API to perform these operations.
    """
    def __init__(self, api_key=TRUENAS_APIKEY, hostname=TRUENAS_HOST, parent_dataset=TRUENAS_PARENT_DATASET,
                 verify_ssl=VERIFY_SSL, starfish_hosts=STARFISH_HOSTS, globus_hosts=GLOBUS_HOSTS):
        if api_key is None:
            raise ValueError("API key is required to connect to TrueNas.")
        self.api_key = api_key
        self.uri = f"wss://{hostname}/websocket"
        self.parent_dataset = parent_dataset
        self.verify_ssl = verify_ssl
        self.starfish_hosts = starfish_hosts
        self.globus_hosts = globus_hosts

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
        return self.__get("filesystem.getacl", project_path.as_posix())
    
    def create_starfish_share(self, project_path: Path):
        return ("sharing.nfs.create", {
            "path": project_path.as_posix(),  # Convert to POSIX path
            "security": ['SYS'],
            "hosts": self.starfish_hosts,
            "maproot_user": 'root',
            "maproot_group": 'wheel',
            "comment": 'starfish',
            "ro": True
        })
    
    def create_globus_share(self, project_path: Path):
        return ("sharing.nfs.create", {
            "path": project_path.as_posix(),  # Convert to POSIX path
            "security": ['SYS'],
            "hosts": self.globus_hosts,
            "comment": 'globus'
        })
    
    def check_share_details(self, project_name: str, quota: int, owner_uid: int, owning_group_gid: int, expected_perms: str = '770'):
        project_path = Path(f"/mnt/{self.parent_dataset}") / project_name
        
        share_details = {"dataset_exists": False,
                         "quota_matches": False,
                         "starfish_share_exists": False,
                         "globus_share_exists": False,
                         "owner_match": False,
                         "group_match": False,
                         "permissions_match": False
        }

        # Check if the dataset already exists
        di = self.get_dataset_info(project_path.as_posix(), details=True)
        if di is None:
            return share_details
        else:
            share_details['dataset_exists'] = True
            share_details['quota_matches'] = di['refquota']['parsed'] == quota
        # Check if the share already exists
        si = self.get_share_info(project_path.as_posix())
        if len(si) == 0:
            return share_details
        else:
            share_details['starfish_share_exists'] = any([i for i in si if i['comment'] == 'starfish'])
            share_details['globus_share_exists'] = any([i for i in si if i['comment'] == 'globus'])
        
        acls = self.get_acls(project_name)
        share_details['owner_match'] = acls['uid'] == owner_uid
        share_details['group_match'] = acls['gid'] == owning_group_gid

        expected_acls = self.generate_acls(expected_perms)
        # Check if the permissions match
        share_details['permissions_match'] = True
        for perm in acls['acl']:
            tag = perm['tag']
            try:
              share_details['permissions_match'] = share_details['permissions_match'] and perm['perms'] == [n['perms'] for n in expected_acls if n['tag'] == tag][0]

            except IndexError:
              share_details['permissions_match'] = False

        # Check if the permissions match
        return share_details


    def create_project_share(self, project_name: str, quota: int, owner_uid: int, owning_group_gid: int,
                             create_dataset: bool = True, create_globus_share: bool = True,
                             create_starfish_share: bool = True):
        """
        Create a dataset and NFS share for an RT project.
        # Create dataset with quota
        # Create the NFS Share for starfish, RO, no_root_squash
        # Create the NFS Share for globus DTNs
        # Set owners (chown)
        # Set permissions (chmod)
        """
        project_path = Path(f"/mnt/{self.parent_dataset}") / project_name
        
        # Create the dataset and share
        # Create the dataset with the specified quota
        # Create the NFS share for starfish
        # Create the NFS share for globus
        # Set the owner and group for the dataset
        # Set the permissions for the dataset
        # Set the ACLs for the dataset
        calls = []
        if create_dataset:
            calls.append(("pool.dataset.create", {
                "name": f"{self.parent_dataset}/{project_name}",
                "type": "FILESYSTEM", #VOLUME OR FILESYSTEM
                "acltype": "POSIX",
                "refquota": quota
            }))
        if create_starfish_share:
            calls.append(self.create_starfish_share(project_path))
        if create_globus_share:
            calls.append(self.create_globus_share(project_path))
        self.__send_calls(calls)  # Send the commands to TrueNas

        self.__send_job("filesystem.chown", {
            "path": project_path.as_posix(),
            "uid": owner_uid,
            "gid": owning_group_gid
        })
        self.__send_job("filesystem.setacl", {
                "path": project_path.as_posix(),
                "dacl": self.generate_acls('770'),
                "acltype": "POSIX1E"
        })
        # we can't set the 
        self.__send_arg_call("pool.dataset.update", f"{self.parent_dataset}/{project_name}", {
            "acltype": "NFSV4",
            "aclmode": "PASSTHROUGH"
        })

    def get_share_info(self, share_path: str):
        """
        Get the share information for a given share name.
        """
        return self.__get("sharing.nfs.query", [["path", "=", share_path]])

    def update_quota(self, dataset_path: str, new_quota: int):
        """
        Update the quota for a given dataset mountpoint.
        """
        dataset_info = self.get_dataset_info(dataset_path, details=True)
        if dataset_info is None:
            raise ValueError(f"Dataset {dataset_path} does not exist.")
        dataset_name = dataset_info['name']
        if dataset_info['refquota']['parsed'] == new_quota:
            raise ValueError(f"Quota for {dataset_path} is already set to {new_quota}. No changes made.")
        if new_quota < 0:
            raise ValueError(f"Quota must be a positive integer. Received: {new_quota}")
        if new_quota < dataset_info['usedbydataset']['parsed']:
            raise ValueError(f"New quota {new_quota} cannot be less than the current used space {dataset_info['usedbydataset']['parsed']}.")
        self.__send_arg_call("pool.dataset.set_quota", dataset_name, [{"id": "REFQUOTA", "quota_type": "DATASET", "quota_value": new_quota}])
        
    def get_dataset_info(self, dataset_path: str, details: bool = False):
        """
        Get the dataset information for a given dataset mountpoint.
        """
        r = self.__get("pool.dataset.details")
        matches = [i for i in r if i['mountpoint'] == dataset_path]
        if matches:
            if details:
                return matches[0]
            else:
                # Return only the mountpoint and quota
                return {
                    'mountpoint': matches[0]['mountpoint'],
                    'used': matches[0]['used']['parsed'],
                    'quota': matches[0]['refquota']['parsed']
                }
        else:
            return None

    def __send_arg_call(self, command: str, *args):
        """
        Send a single command to TrueNas with the provided arguments.
        """
        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            c.call("auth.login_with_api_key", self.api_key)
            c.ping()
            print(f"Sending command: {command} with args: {args}")
            c.call(command, *args)

    def __send_calls(self, commands: list[tuple[str, dict]]):

        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            c.call("auth.login_with_api_key", self.api_key)
            c.ping()
            for command, payload in commands:
                # Send the command to TrueNas
                print(f"Sending command: {command} with payload: {payload}")           
                c.call(command, payload)

    def __send_job(self, command: str, payload: dict):

        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            c.call("auth.login_with_api_key", self.api_key)
            c.ping()
            print(f"Sending job: {command} with payload: {payload}")           
            c.call(command, payload, job=True)
    
    def __get(self, command: str, identifier: str = None):
        """
        Get the result of a command from TrueNas.
        """
        with Client(uri=self.uri , verify_ssl=self.verify_ssl) as c:
            c.call("auth.login_with_api_key", self.api_key)
            c.ping()
            if identifier:
                print(f"Getting command: {command} with identifier: {identifier}")
                return c.call(command, identifier)
            else:
                print(f"Getting command: {command}")
                return c.call(command)           

