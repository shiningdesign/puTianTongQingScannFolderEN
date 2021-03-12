u'''
#################################
##coding:utf-8
#  HolyPipe
#
#################################

original
http://www.honglianimation.com/res/pttq.zip

note:
https://mp.weixin.qq.com/s/0Wxru1Flyxn2XRwofETM5A
'''

__version__ = '20200623.0'

import sys, os, subprocess, json,time,datetime, glob, tempfile
import getpass, platform
import shutil
from stat import ST_ATIME,ST_CTIME,ST_MTIME
__gui__ = 'missing'
try:
    from PySide2 import QtWidgets as qw,  QtCore
    __gui__ = 'PySide2'
except:
    from PySide import QtGui as qw, QtCore
    __gui__ = 'PySide'


#region scan core
#directory path to scan//nas/data/PipePrjWork/putiantongqing/end with /
#tryFix 1 is repair 0 is no repair
#recursion 1 is recursive 0 is not recursive
#logPath scan"//nas/data/PipePrjWork/putiantongqing/pan_yao.txt"
#skipLog 0 is continous scan 1 is rescan
def Scanner_ErrorFile_Main(directory,tryFix,recursion,logPath,skipLog, 
                                                uiInfoCallback=lambda info:None, 
                                                uiAddVirusCallback=lambda filePath:None):
    #if rescan delete log after change dont delete log
    #if skipLog == 1 and os.path.isfile(logPath):
    #    os.remove(logPath)
    timeNow = datetime.datetime.now()
    timeNowStr = timeNow.strftime("%Y-%m-%d %H:%M:%S")
    writeLog(logPath,timeNowStr+',scann Folder Path:'+directory+'\n')
    allMa = []
    errFileList = []
    if recursion:#recursivescan inside the folder for all ma and directly scan prevent server root directory recursive report error and can't continous scan
        ScanFilesFromFolder(directory,logPath,skipLog,prefix=None,postfix='.ma',  tryFix=tryFix,
                                    uiInfoCallback=uiInfoCallback,
                                    uiAddVirusCallback=uiAddVirusCallback)
    else:#not recursivescan inside the folder for all ma
        getAllFile = os.listdir(directory)
        #continous scan read recored info from log file for scanned directories
        logInfo = ''
        if skipLog == 0 and os.path.isfile(logPath):
            f = open(logPath,'r')
            logInfo = f.read()
            f.close()
        for mm in getAllFile:
            #if scaned, then pass
            if skipLog == 0 and logInfo and logInfo.count(directory+mm):
                print(directory+mm+' is already scann\n')
                continue
            if mm.endswith('.ma'):
                allMa.append(directory+mm)
        #based on scaned ma file list, do next step
        for i,mm in enumerate(allMa):
            uiInfoCallback('scaning (%i/%i): %s'%(i, len(allMa), mm))
            isErrorFile = DoScanFile(mm,tryFix,logPath,skipLog)
            if isErrorFile:
                errFileList.append(mm)
                uiAddVirusCallback(mm)
        return errFileList

def ScanFilesFromFolder(directory,logPath,skipLog,prefix=None,postfix=None, 
                                        uiInfoCallback=lambda info:None, 
                                        uiAddVirusCallback=lambda filePath:None,
                                        tryFix=False):
    files_list=[]
    #logInfo = ''
    #continous scan, read log file for scanned file info
    #log file record format: True d:/.../aa.ma    tryFix  202006221500    1024L
    fileInLogDic = {}
    alreadyExaminFiles = []
    if skipLog == 0 and os.path.isfile(logPath):
        f = open(logPath,'r')
        lines = f.readlines()
        f.close()
        for mm in range(len(lines)):
            getLineInfo = lines[mm].decode('utf-8').strip().split('\t')
            if len(getLineInfo) == 5:
                fileInLogDic[getLineInfo[2]] = {'virus':getLineInfo[0],'killed':getLineInfo[1],'mtime':getLineInfo[3],'size':getLineInfo[4]}
        alreadyExaminFiles = fileInLogDic.keys()

    def appendScanFile(filePath):
        files_list.append(filePath)
        uiInfoCallback('scaning (%i): %s'%(len(files_list),  filePath))
        isErrorFile = DoScanFile(filePath,tryFix,logPath,skipLog, uiAddVirusCallback=uiAddVirusCallback)

    for root, sub_dirs, files in os.walk(directory):
        uiInfoCallback('gathering files (%i): '% len(files_list)+root+'\\')
        for special_file in files:
            if not special_file.lower().endswith('.ma'):
                continue
            uiInfoCallback('gathering files (%i): '% len(files_list)+os.path.join(root,special_file) )
            if postfix:
                if special_file.endswith(postfix):
                    if alreadyExaminFiles:#not first time scan
                        if alreadyExaminFiles.count(os.path.join(root,special_file)):#file has been scanned
                            if time.strftime("%Y%m%d%H%M%S",time.localtime(os.path.getmtime(os.path.join(root,special_file)))) == fileInLogDic.get(os.path.join(root,special_file)).get('mtime'):#file modified time and log recored last scaned modified time look the same, means between this can and last scan, file has not been changed
                                if fileInLogDic.get(os.path.join(root,special_file)).get('virus') == 'True' and fileInLogDic.get(os.path.join(root,special_file)).get('killed') == 'False':#last time proved with infection, and scanned only not cleaned, need rescan and cleanup
                                    appendScanFile(os.path.join(root,special_file))
                                else:
                                    continue
                            else:#though file has been scanned last time, but file has been changed , need rescan
                                appendScanFile(os.path.join(root,special_file))
                        else:#file has not been scanned
                            appendScanFile(os.path.join(root,special_file))
                    else:#first time scan
                        appendScanFile(os.path.join(root,special_file))
            elif prefix:
                if special_file.startswith(prefix):
                    if alreadyExaminFiles:#not first time scan
                        if alreadyExaminFiles.count(os.path.join(root,special_file)):#file has been scanned
                            if time.strftime("%Y%m%d%H%M%S",time.localtime(os.path.getmtime(os.path.join(root,special_file)))) == fileInLogDic.get(os.path.join(root,special_file)).get('mtime'):#file modified time and log recored last scaned modified time look the same, means between this can and last scan, file has not been changed
                                if fileInLogDic.get(os.path.join(root,special_file)).get('virus') == 'True' and fileInLogDic.get(os.path.join(root,special_file)).get('killed') == 'False':#last time proved with infection, and scanned only not cleaned, need rescan and cleanup
                                    appendScanFile(os.path.join(root,special_file))
                                else:
                                    continue
                            else:#though file has been scanned last time, but file has been changed , need rescan
                                appendScanFile(os.path.join(root,special_file))
                        else:#file has not been scanned
                            appendScanFile(os.path.join(root,special_file))
                    else:#first time scan
                        appendScanFile(os.path.join(root,special_file))
            else:
                #if scaned, then pass
                if skipLog == 0 and alreadyExaminFiles and alreadyExaminFiles.count(os.path.join(root,special_file)):
                    print(os.path.join(root,special_file)+' is already scanned\n')
                    continue
                appendScanFile(os.path.join(root,special_file))
                if alreadyExaminFiles:#not first time scan
                    if alreadyExaminFiles.count(os.path.join(root,special_file)):#file has been scanned
                        if time.strftime("%Y%m%d%H%M%S",time.localtime(os.path.getmtime(os.path.join(root,special_file)))) == fileInLogDic.get(os.path.join(root,special_file)).get('mtime'):#file modified time and log recored last scaned modified time look the same, means between this can and last scan, file has not been changed
                            if fileInLogDic.get(os.path.join(root,special_file)).get('killed') == False and tryFix:#last time only scaned but not cleaned, need cleanup for this time, and need rescan to do cleaup
                                appendScanFile(os.path.join(root,special_file))
                            else:
                                continue
                        else:#though file has been scanned last time, but file has been changed , need rescan
                            appendScanFile(os.path.join(root,special_file))
                    else:#file has not been scanned
                        appendScanFile(os.path.join(root,special_file))
                else:#first time scan
                    appendScanFile(os.path.join(root,special_file))
    return files_list

def DoScanFile(maPath,tryFix,logPath,skipLog, uiAddVirusCallback=lambda filePath:None):
    try:
        print('scanning: %s'%maPath)
        maPath = LongLongFile(maPath)
        errFile = 0
        f = open(maPath,'r')
        lines = f.readlines()
        lenLines = len(lines)
        errLine = []
        for mm in range(lenLines):
            if lines[mm].count('createNode script -n "'):
                #fopen  fprint  fcloseif all appear, means been infected
                isFopen = 0
                isFprint = 0
                isFclose = 0
                #print '-------------start---------------'
                errLine.append(mm)
                tt = mm + 1
                while not lines[tt].startswith('createNode ') and not lines[tt].startswith('select ') and not lines[tt].startswith('select ') and not lines[tt].startswith('connectAttr ') :
                    isError = IsHaveKeyword(lines[tt])
                    if isError:
                        errFile = 1
                    if lines[tt].count('fopen'):
                        isFopen = 1
                    if lines[tt].count('fprint'):
                        isFprint = 1
                    if lines[tt].count('fclose'):
                        isFclose = 1
                    errLine.append(tt)
                    tt = tt + 1
                    if tt>=lenLines:
                        break
                if errFile == 0:
                    if isFopen == 1 and isFprint == 1 and isFclose == 1:
                        print('have fopen  fprint  fclose')
                        errFile = 1
        f.close()
        if tryFix and errFile:
            if errLine:
                #before repair, back up with this extension.putiantongqing
                copyFrom = maPath
                copyTo = maPath+'.putiantongqing'
                shutil.copy(copyFrom,copyTo)
                file_stat = os.stat(copyFrom)
                os.utime(copyTo, (file_stat[ST_CTIME], file_stat[ST_MTIME]))
                #os.remove(maPath)
                with open(maPath, "w",) as f:
                    for mm in range(len(lines)):
                        if errLine.count(mm):
                            continue
                        else:
                            f.write(lines[mm])
                f.close()
        #write into log
        #get ma file modified time and file sizewrite into log
        tryFixInfo = 'False'
        if tryFix:
            tryFixInfo = 'True'
        mTime= time.strftime("%Y%m%d%H%M%S",time.localtime(os.path.getmtime(maPath)))
        fileSize = os.path.getsize(maPath)
        if errFile:
            writeLog(logPath,'True\t'+tryFixInfo+'\t'+maPath+'\t'+str(mTime)+'\t'+str(fileSize)+'\n')
        else:
            writeLog(logPath,'False\t'+tryFixInfo+'\t'+maPath+'\t'+str(mTime)+'\t'+str(fileSize)+'\n')
        if errFile:
            uiAddVirusCallback(maPath)
        return errFile
    except:
        message = traceException(makeError=0)
        writeLog(logPath+'.except',maPath+'\n'+message+'\n')

def IsHaveKeyword(lineInfo):
    keyWord = ['UI_Mel_Configuration_think',
                   'UI_Mel_Configuration_think_a',
                   'UI_Mel_Configuration_think_b',
                   'autoUpdateAttrEd_SelectSystem',
                   'autoUpdatcAttrEd',
                   'autoUpdatoAttrEnd',
                   'fuck_All_U',
                   '$PuTianTongQing']
    for mm in keyWord:
        if lineInfo.count(mm):
            return 1
    return 0

def writeLog(logPath,infoStr):
    f = open(logPath, 'a')
    f.write(infoStr.encode('utf-8'))
    f.close()

def LongLongFile(result):
    if len(result)>=260:
        if result[2:3]!=':?':
            if result[:2] in ['\\\\','//']:
                result = r'\\?\UNC\%s'%result[2:].replace('/','\\')
            else:
                result = r'\\?\%s'%result.replace('/','\\')
        else:
            result = result.replace('/','\\')
    return result

def traceException(makeError=0):
    import traceback, StringIO
    fp = StringIO.StringIO()
    traceback.print_exc(file=fp)
    message = fp.getvalue()
    if message.split('\n')[-2][0:len('SystemExit')] != 'SystemExit':
        if makeError:
            raise RuntimeError, message
            pass
        else:
            print(message)
            return message
# endregion scan core

# region gui
class VirusOp():
    def __init__(self):
        self.closeExistingWindow()
        self.show_ui()

    def closeExistingWindow(self):
        for qt in qw.QApplication.topLevelWidgets():
            try:
                if qt.windowTitle() == u'Virus Scan Clean':
                    qt.close()
            except:
                pass

    def getFileDialogText(self):
        scanPath = self.inputPathDir.getExistingDirectory()
        self.filePath.setText(scanPath)

    def getLogDialogText(self):
        savePath = self.logDir.getOpenFileName()
        self.logPath.setText(savePath)

    def getFilePath(self):
        curFilePath = self.filePath.text()
        print('scan path is:')
        print(curFilePath)
        print('\n')
        return curFilePath + '\\'

    def getLogPath(self):
        curLogPath = self.logPath.text()
        print('log path is:')
        print(curLogPath)
        print('\n')
        return curLogPath

    def getScanMode(self):
        curMode = self.modeCB.currentText()
        print('scan mode is:')
        print(curMode)
        scanMode = 0
        if curMode == u'rescan':
            scanMode = 1
        if curMode == u'continous scan':
            scanMode = 0
        print(scanMode)
        print('\n')
        return scanMode

    def getCleanState(self):
        curState = self.scanCleanBtn.checkState()
        print('clean state is:')
        print(curState)
        cleanState = 0
        if curState == 0:
            cleanState = 0
        else:
            cleanState = 1
        print(cleanState)
        print('\n')
        return cleanState

    def getWalkState(self):
        curState = self.scanWalkBtn.checkState()
        print('walk state is:')
        print(curState)
        walkState = 0
        if curState == 0:
            walkState = 0
        else:
            walkState = 1
        print(walkState)
        print('\n')
        return walkState

    def addList(self, virusList):
        scanModeParam = self.getScanMode()
        if scanModeParam:
            self.fileList.clear()
        for iFile in virusList:
            self.fileList.addItem(iFile)
        print('finish adding\n')

    def getRefState(self, event):
        refState = 0
        if self.refBtn1.isChecked():
            refState = 0
        if self.refBtn2.isChecked():
            refState = 1
        if self.refBtn3.isChecked():
            refState = 2
        self.query.close()

        subPaths = []
        if event.mimeData().hasUrls():
            event.setDropAction(QtCore.Qt.LinkAction)
            event.accept()
            for url in event.mimeData().urls():
                filePath = unicode(url.toLocalFile())
                print(filePath)
                if os.path.isfile(filePath) and filePath.lower().endswith('.ma'):
                    subPaths.extend([filePath])
                elif os.path.isdir(filePath):
                    subPaths.extend([x for x in glob.glob(filePath+'/*') if os.path.isfile(x) and x.lower().endswith('.ma')])
        elif event.mimeData().hasText():
            event.setDropAction(QtCore.Qt.LinkAction)
            event.accept()
            for text in event.mimeData().text().splitlines():
                # filePath = text.split('\t')[-1].replace('"','')
                for iPart in text.split('\t'):
                    tempPath = iPart.replace('"','')
                    if os.path.isfile(tempPath) and tempPath.lower().endswith('.ma'):
                        subPaths.extend([tempPath])
                    elif os.path.isdir(tempPath):
                        subPaths.extend([x for x in glob.glob(tempPath+'/*') if os.path.isfile(x) and x.lower().endswith('.ma')])
        
        def recursiveGetRef(fileName, outList=[], cacheDict={}, recursive=True):
            fileName = os.path.expandvars(fileName).replace('\\', '/')
            if not os.path.isfile(fileName):
                return
            if fileName not in cacheDict:
                cacheDict[fileName] = 1
                outList.append(fileName)
                self.fileList.addItem('\t'+fileName)
                qw.QApplication.instance().processEvents()
            curFile = open(u'%s' % fileName, 'rb')
            curLine = curFile.readline()
            while curLine:
                while not curLine.strip().endswith(';'):
                    curLine += curFile.readline()
                if 'file -rdi ' in curLine and '.ma' in curLine:
                    maPath = os.path.expandvars(curLine.split('\"')[-2]).replace('\\', '/')
                    if not os.path.isfile(maPath):
                        maPath = os.path.dirname(fileName)+'/'+os.path.basename(maPath)
                    if not os.path.isfile(maPath):
                        print('Referenc path not accessable: %s'%maPath)
                        curLine = curFile.readline()
                        continue
                    if maPath not in cacheDict:
                        recursiveGetRef(maPath, outList=outList, cacheDict=cacheDict, recursive=True) if recursive else None
                if 'file -r ' in curLine and '.ma' in curLine:
                    maPath = os.path.expandvars(curLine.split('\"')[-2]).replace('\\', '/')
                    if not os.path.isfile(maPath):
                        maPath = os.path.dirname(fileName)+'/'+os.path.basename(maPath)
                    if not os.path.isfile(maPath):
                        curLine = curFile.readline()
                        print('Referenc path not accessable: %s'%maPath)
                        continue
                    
                    if maPath not in cacheDict:
                        recursiveGetRef(maPath, outList=outList, cacheDict=cacheDict, recursive=True) if recursive else None

                if 'requires ' in curLine:
                    break
                curLine = curFile.readline()
            curFile.close()

        listedPathCache = {}
        if refState == 0:
            for iSubPath in sorted(list(set(subPaths))):
                self.fileList.addItem('\t'+iSubPath)
                listedPathCache[iSubPath.split('\t')[-1].replace('\\','/')] = 1

        if refState == 1:
            print(u'one')
            for i, iSubPath in enumerate(subPaths):
                recursiveGetRef(iSubPath, outList=subPaths, cacheDict=listedPathCache, recursive=False)

        if refState == 2:
            print(u'all')
            for i, iSubPath in enumerate(subPaths):
                recursiveGetRef(iSubPath, outList=subPaths, cacheDict=listedPathCache, recursive=True)


    def refQuery(self, event):

        self.query = qw.QDialog()
        self.query.setWindowFlags(QtCore.Qt.Window|QtCore.Qt.WindowStaysOnTopHint)
        self.query.setWindowTitle('Query')

        vLay = qw.QVBoxLayout()
        self.query.setLayout(vLay)

        scanLabel = qw.QLabel(u'scan maya included reference')
        vLay.addWidget(scanLabel)

        hLay = qw.QHBoxLayout()
        vLay.addLayout(hLay)

        self.refBtn1 = qw.QRadioButton(u'do not include reference')
        self.refBtn1.setChecked(1)
        hLay.addWidget(self.refBtn1)

        self.refBtn2 = qw.QRadioButton(u'include first level reference')
        hLay.addWidget(self.refBtn2)

        self.refBtn3 = qw.QRadioButton(u'include all level reference')
        hLay.addWidget(self.refBtn3)

        hLayRecovery = qw.QHBoxLayout()
        vLay.addLayout(hLayRecovery)
        hLayRecovery.addStretch()

        recoveryButton = qw.QPushButton(u'confirm')
        recoveryButton.clicked.connect(lambda a=1,e=event: self.getRefState(e))
        hLayRecovery.addWidget(recoveryButton)

        vLay.addStretch()
        self.query.exec_()

    def getList(self):
        itemNum = self.fileList.count()
        itemList = []
        self.listDict = {}
        for i in range(itemNum):
            curItem = self.fileList.item(i)
            curItemName = curItem.text()
            itemList.append(curItemName)
            self.listDict[curItemName.split('\t')[-1]] = i
            print(curItemName)
        print(itemList)
        return itemList

    def emptyList(self):
        removeList = self.fileList.selectedItems()
        rows = sorted([self.fileList.row(item) for item in removeList])[::-1]
        for row in rows:
            removedItem = self.fileList.takeItem(row)
            print('removed from list:', removedItem.text())

    def scanList(self):
        print('start to scan list\n')
        itemList = self.getList()
        print(itemList)
        for iMa in itemList:
            print('start cleaning\n')
            print(iMa)
            maPath = iMa.split('\t')[-1]
            DoScanFile(maPath, 1, self.getLogPath(), self.getScanMode(), uiAddVirusCallback=lambda path:self.updateScanned(path))
            print('finish cleaning\n')

    def updateScanned(self,filePath):
        self.fileList.item(self.listDict[filePath]).setText('cleaned\t'+filePath)

    def scanFuc(self):
        print('start to scan')

        filePathParam = self.getFilePath()
        print('scan path is:')
        print(filePathParam)

        logPathParam = self.getLogPath()
        if not os.path.isdir(os.path.dirname(logPathParam)):
            os.makedirs(os.path.dirname(logPathParam))
        print('log path is:')
        print(logPathParam)
        
        scanModeParam = self.getScanMode()
        print('scan mode is:')
        print(scanModeParam)

        cleanStateParam = self.getCleanState()
        print('clean state is:')
        print(cleanStateParam)

        walkStateParam = self.getWalkState()
        print('walk state is:')
        print(walkStateParam)

        print('start to scan and clean\n')
        virusFileList = Scanner_ErrorFile_Main(filePathParam, cleanStateParam, walkStateParam, logPathParam, scanModeParam, 
                                                                uiInfoCallback=lambda info:self.uiInfo(info),
                                                                uiAddVirusCallback=lambda filePath, clean=cleanStateParam:self.fileList.addItem(('virus\t' if not clean else 'cleaned\t')+filePath))
        print(virusFileList)
        print('\n')
        print('finish scanning and cleaning\n')

    def uiInfo(self, info):
        self.infoLabel.setText(info)
        qw.QApplication.instance().processEvents()

    def show_ui(self):

        self.ui = qw.QWidget()
        self.ui.resize(800,500)
        self.ui.setWindowFlags(QtCore.Qt.Window|QtCore.Qt.WindowStaysOnTopHint)
        self.ui.setWindowTitle(u'Virus Scan Clean')

        topLay = qw.QVBoxLayout()
        topLay.setContentsMargins(0,0,0,0)
        self.ui.setLayout(topLay)

        titlebar = qw.QLabel(u'  Hongli Animation    Ver: %s    GUI: %s    '%(__version__, __gui__))
        titlebar.setStyleSheet('background-color:rgb(16,128,196); color:white; font-size:16px')
        titlebar.setFixedHeight(30)
        topLay.addWidget(titlebar)

        mainLay = qw.QVBoxLayout()
        mainLay.setContentsMargins(10,0,10,10)
        topLay.addLayout(mainLay)

        
        inputLabel = qw.QLabel(u'Input Scan Directory:')
        mainLay.addWidget(inputLabel)

        pathLay = qw.QHBoxLayout()
        mainLay.addLayout(pathLay)

        self.filePath = qw.QLineEdit()
        self.filePath.setMinimumWidth(400)
        pathLay.addWidget(self.filePath)

        viewButton = qw.QPushButton(u'browse')
        pathLay.addWidget(viewButton)
        viewButton.clicked.connect(lambda *args: self.getFileDialogText())

        self.inputPathDir = qw.QFileDialog()

        user = getpass.getuser()
        pc = platform.node()
        print('user is: ' + user)
        print('pc is: ' + pc)
        print('\n')
        defaultLogPath = '//nas/data/PipePrjWork/__UniPipe_Test/PuTianTongQing_logs/%s_%s_virusScan.log' % (user, pc)
        if not os.path.isdir('//nas/data/PipePrjWork/__UniPipe_Test'):
            defaultLogPath = tempfile.gettempdir().replace('\\','/')+'/PuTianTongQing_logs/%s_%s_virusScan.log' % (user, pc)
        print('default log path is: ' + defaultLogPath)
        print('\n')
        
        logLabel = qw.QLabel(u'Scan Log Path:')
        mainLay.addWidget(logLabel)

        logLay = qw.QHBoxLayout()
        mainLay.addLayout(logLay)

        self.logPath = qw.QLineEdit()
        self.logPath.setMinimumWidth(400)
        logLay.addWidget(self.logPath)
        self.logPath.setText(defaultLogPath)

        logButton = qw.QPushButton(u'browse')
        logLay.addWidget(logButton)
        logButton.clicked.connect(lambda *args: self.getLogDialogText())

        self.logDir = qw.QFileDialog()
        self.logDir.setDirectory('//nas/data/PipePrjWork/__UniPipe_Test')

        modeLay = qw.QHBoxLayout()
        mainLay.addLayout(modeLay)
        modeLay.addStretch()

        modeLabel = qw.QLabel(u'scan mode:')
        modeLay.addWidget(modeLabel)

        self.modeCB = qw.QComboBox()
        modeLay.addWidget(self.modeCB)
        self.modeCB.setEditable(0)
        self.modeCB.setMinimumWidth(185)
        self.modeCB.addItem(u'continous scan')
        self.modeCB.addItem(u'rescan')

        stateLay = qw.QHBoxLayout()
        mainLay.addLayout(stateLay)
        stateLay.addStretch()

        self.scanCleanBtn = qw.QCheckBox(u'scan virus then clean them')
        stateLay.addWidget(self.scanCleanBtn)

        self.scanWalkBtn = qw.QCheckBox(u'include all subfolder')
        self.scanWalkBtn.setChecked(1)
        stateLay.addWidget(self.scanWalkBtn)

        confirmLay = qw.QHBoxLayout()
        mainLay.addLayout(confirmLay)

        self.infoLabel = qw.QLabel('')
        confirmLay.addWidget(self.infoLabel)
        confirmLay.addStretch()

        self.scanBtn = qw.QPushButton(u'scan directory')
        self.scanBtn.setStyleSheet('background-color:rgb(20,196,255); color:white; font-size:16px')
        self.scanBtn.clicked.connect(lambda *args: [self.scanBtn.setEnabled(0), self.scanFuc(), self.scanBtn.setEnabled(1)])
        confirmLay.addWidget(self.scanBtn)
        listLabel = qw.QLabel(u'File List:(drag file or path for scan)')
        mainLay.addWidget(listLabel)

        self.fileList = qw.QListWidget()
        self.fileList.setMinimumWidth(400)
        self.fileList.setAcceptDrops(True)
        self.fileList.setSelectionMode(qw.QAbstractItemView.ExtendedSelection)

        def dragEnterEvent(item, e):
            e.accept()

        def dragMoveEvent(item, e):
            e.accept()

        def dropEvent(item, event):
            event.accept()
            self.refQuery(event)

        self.fileList.dragEnterEvent = lambda e: dragEnterEvent(self.fileList, e)
        self.fileList.dragMoveEvent = lambda e: dragMoveEvent(self.fileList, e)
        self.fileList.dropEvent = lambda e: dropEvent(self.fileList, e)

        mainLay.addWidget(self.fileList)


        cleanLay = qw.QHBoxLayout()
        self.emptyBtn = qw.QPushButton(u'clean selected files in the list')
        self.emptyBtn.clicked.connect(lambda *args: self.emptyList())
        cleanLay.addWidget(self.emptyBtn)

        mainLay.addLayout(cleanLay)
        cleanLay.addStretch()

        self.cleanBtn = qw.QPushButton(u'scan the list and cleanup')
        self.cleanBtn.setStyleSheet('background-color:rgb(20,196,255); color:white; font-size:16px')
        self.cleanBtn.clicked.connect(
            lambda *args: [self.cleanBtn.setEnabled(0), self.scanList(), self.cleanBtn.setEnabled(1)])
        cleanLay.addWidget(self.cleanBtn)

        self.ui.show()
# endregion gui
def main():
    app = qw.QApplication([]) if not qw.QApplication.instance() else None
    VirusOp()
    app.exec_() if app else None
if __name__ == '__main__':
    main()
