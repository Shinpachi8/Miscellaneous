-- MySQL dump 10.13  Distrib 5.7.13, for osx10.11 (x86_64)
--
-- Host: 127.0.0.1    Database: githubscan
-- ------------------------------------------------------
-- Server version	5.5.53

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `githubinfo`
--

DROP TABLE IF EXISTS `githubinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `githubinfo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hashvalue` char(32) DEFAULT NULL,
  `url` text,
  `email` varchar(100) DEFAULT NULL,
  `time` varchar(11) DEFAULT NULL,
  `checked` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `githubinfo`
--

LOCK TABLES `githubinfo` WRITE;
/*!40000 ALTER TABLE `githubinfo` DISABLE KEYS */;
INSERT INTO `githubinfo` VALUES (1,'c927c54fcb941fcaab1a37ebad5e4991','https://raw.githubusercontent.com/SasaHao/test/d5a5e0fc926cb733868cc61cb25b7d2393083013/ad_show_test/shell/.svn/text-base/sendMail.py.svn-base','arksystem@letv.com','2017-09-24',0);
/*!40000 ALTER TABLE `githubinfo` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2017-09-24 20:59:49

CREATE TABLE `visiturl` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hashvalue` char(32) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8