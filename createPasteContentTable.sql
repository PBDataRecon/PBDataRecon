CREATE TABLE PBDataRecon.PasteContent
(
 PasteContentID    MEDIUMINT(9) NOT NULL AUTO_INCREMENT,
   
keyval              VARCHAR(25)
                         CHARACTER SET utf8
                         COLLATE utf8_general_ci
                         NOT NULL
                         DEFAULT 'error',
 Paste            MEDIUMTEXT
                         CHARACTER SET utf8
                         COLLATE utf8_general_ci
                         NULL,
  pasteType         VARCHAR(25)
                         CHARACTER SET utf8
                         COLLATE utf8_general_ci
                         NULL,
   PRIMARY KEY(`PasteContentID`)
)
ENGINE INNODB
ROW_FORMAT DEFAULT;
