# puTianTongQingScannFolderEN based on original 20200623 Chinese version from HongLiAnimation
the English ascii code translated version of Maya Mel PuTianTongQing virus scan and clean tool from honglianimation.com, 
and I added one drag and drop install.mel file for easy maya install onto shelf, and I also added one auto launch dos cmd file for easy launch from desktop. 
also I added a scanner icon for it (it shows in Maya shelf and you need to setup your own for batch shortcut icon). 
  * https://www.iconsdb.com/orange-icons/scanner-icon.html

It is based on this article, 
https://mp.weixin.qq.com/s/uoPPLvE_8LNKlOcHxkeRxw

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
  * as mostly likely some bad guys with improve the virus code for fun, and circle it around for future, you probaly need to keep update the tool to make it up to date without future similar virus, as there may be so many alternative way of writting it, so those Keyword detection method may not one for all.
  * currently, this version is detecting by check scriptNode with content having fopen/fprint/fclose words, bascially, those scriptNode trying to writing something into your file, which doesn't make sense for a normal scriptNode, so it detects by that pattern
