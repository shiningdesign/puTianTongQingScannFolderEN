# puTianTongQingScannFolderEN 20200623.0.mod.v2

update log:

v1.2: (2021.03.10)
  * add more bad word detection and support generic file detection and fix for future Maya virus

In DoScanFile function, I add ban_word_list, so it can support more generic file accesing Maya virus detection, and it also support fix the 2nd wave of Maya "virus", which was designed to use "virus" method to fix origianl puTianTongQing virus. in which it will warns your file no issue by printing Chinese line "贼健康"

```
ban_word_list = ['PuTianTongQing','fopen','fprint','fclose','with open','.write','makedirs','shutil','copyfile']
```

Detail by the 2nd "virus" author (顶天立地智慧大将军): https://mp.weixin.qq.com/s/lFcsQjQdjVbMNgprdIEvLw

Due Maya binary nature, this tool only support MA text file, for binary file, you have to use my other tool SuperManScan to do scan and fix in Maya and slow due to loading all content inside Maya to to clean, (will release soon)

# puTianTongQingScannFolderEN based on original 20200623 Chinese version from HongLiAnimation

![puTianTongQingScannFolderEN_20200623_1.JPG](notes/puTianTongQingScannFolderEN_20200623_1.JPG?raw=true)
![puTianTongQingScannFolderEN_20200623_2.JPG](notes/puTianTongQingScannFolderEN_20200623_2.JPG?raw=true)

the English ascii code translated version of Maya Mel PuTianTongQing virus scan and clean tool from honglianimation.com, 
and I added one drag and drop install.mel file for easy maya install onto shelf, and I also added one auto launch dos cmd file for easy launch from desktop. 
also I added a scanner icon for it (it shows in Maya shelf and you need to setup your own for batch shortcut icon). 
  * https://www.iconsdb.com/orange-icons/scanner-icon.html

It is based on this article, 
https://mp.weixin.qq.com/s/uoPPLvE_8LNKlOcHxkeRxw

more info
https://mp.weixin.qq.com/s/Y12SquhWU3CLK8GXVNCOjg

and the tool is orginally in Chinese, and download from here:
www.honglianimation.com/res/pttq.zip

Then I translated into English and Ascii code only, so those who use English only system can run the tool without error and can understand the interface and code comments.

Notes:
  * right now this tool only fix MA file, no mb file fix, for mb file fix, need to use Maya autodesk tool
  * Maya autodesk tool download: https://apps.autodesk.com/MAYA/en/Detail/Index?id=8637238041954239715&os=Win64&appLang=en
  * sample code with autodesk tool: https://gist.github.com/zclongpop123/3b3cfb1dde7d347a4ccdd1ad29b1cae2

How to Use Instruction:
  * download the whole package as zip, unpack
  * use the dos Batch file to run as standalone windows tool (need python and pyside installed first)
  * or drag the install_puTianTongQingScannFolderEN.mel into maya viewport to put on current shelf tool, and run directly inside maya
  * example is inside the notes
  
Final Notes:
  * as mostly likely some bad guys will improve the virus code for fun, and circle it around for future, you probaly need to keep updating the tool to make it up to date with those future similar virus, as there may be so many alternative ways of writing it, thus those Keyword detection method may not fit once for all.
  * currently, this version is detecting by checking scriptNode with content including fopen/fprint/fclose words, bascially, those scriptNodes are trying to write something into your file, which doesn't make sense for a normal scriptNode, so it detects by that pattern
