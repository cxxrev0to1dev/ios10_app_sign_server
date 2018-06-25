import os
from apple_signed_server import *

if __name__ == '__main__':
	app_ver_id = "1035192537"
	os.chdir(os.path.dirname(os.path.realpath(__file__)))
	devloper_conf = os.path.join(os.path.dirname(os.path.realpath(__file__)), "developer")
	devloper_conf = os.path.join(devloper_conf, "devloper.conf")
	devloper_conf = os.path.join(devloper_conf, "devloper.conf.plist")
	devloper_conf = plistlib.readPlist(devloper_conf)
	for dev_conf in devloper_conf['devs']:
		try:
			dev_dirs = os.path.join(os.path.dirname(os.path.realpath(__file__)), "developer")
			dev_dirs = os.path.join(dev_dirs, dev_conf["developer"])
			####################################app src###############################################
			in_app = os.path.join(os.path.dirname(os.path.realpath(__file__)), "app")
			in_app = os.path.join(in_app, app_ver_id)
			in_app = Signer.GetRootFromApp(in_app)
			print in_app
			####################################ipa dst###############################################
			out_ipa = os.path.join(os.path.dirname(os.path.realpath(__file__)), "developer")
			out_ipa = os.path.join(out_ipa, dev_conf["developer"])
			out_ipa = os.path.join(out_ipa, "ables_app")
			out_ipa = os.path.join(out_ipa, str(app_ver_id + ".ipa"))
			####################################app sign to ipa#######################################
			mb = os.path.join(dev_dirs, str(dev_conf["developer"] + ".mobileprovision"))
			cert_info = plistlib.readPlist(os.path.join(dev_dirs, str(dev_conf["developer"] + ".plist")))
			src_ipa = Signer.SignatureImpl("DeviceIdToUpdate",mb,cert_info['certificateName'],in_app,True)
			shutil.copyfile(src_ipa,out_ipa)
			print out_ipa
		except:
			pass