CREATE TABLE PBDataRecon.MetaDataValues
(
   MetaDataValuesID    MEDIUMINT(9) NOT NULL AUTO_INCREMENT,
   keyval                VARCHAR(25)
                           CHARACTER SET utf8
                           COLLATE utf8_general_ci
                           NOT NULL,
   date                VARCHAR(25)
                           CHARACTER SET utf8
                           COLLATE utf8_general_ci
                           NOT NULL,
   size                  INT(11) NULL,
   user                  VARCHAR(25)
                           CHARACTER SET utf8
                           COLLATE utf8_general_ci
                           NULL,
   pasteTime           INT(11) NOT NULL,
   title                 VARCHAR(255)
                           CHARACTER SET utf8
                           COLLATE utf8_general_ci
                           NULL,
   syntax                VARCHAR(35)
                           CHARACTER SET utf8
                           COLLATE utf8_general_ci
                           NULL,
   expire                VARCHAR(25)
                           CHARACTER SET utf8
                           COLLATE utf8_general_ci
                           NULL,
   PasteType           VARCHAR(25)
                           CHARACTER SET utf8
                           COLLATE utf8_general_ci
                           NULL,
   PRIMARY KEY(`MetaDataValuesID`)
)
ENGINE INNODB
ROW_FORMAT DEFAULT
