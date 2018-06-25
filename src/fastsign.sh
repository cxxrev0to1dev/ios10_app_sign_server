#!/bin/bash

#sudo gem install fastlane
fastlane fastlane-credentials add --username sib877@163.com --password We110011
fastlane cert -u sib877@163.com --development
#fastlane sigh -a com.krausefx.app -u sib877@163.com --development
#fastlane produce -u sib877@163.com -a com.sssss.sjkhdj.sdjhghsg --skip_itc