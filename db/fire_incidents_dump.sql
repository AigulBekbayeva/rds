-- MySQL dump 10.13  Distrib 8.0.39, for Win64 (x86_64)
--
-- Host: localhost    Database: fire_incidents
-- ------------------------------------------------------
-- Server version	8.0.39

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `alembic_version`
--

DROP TABLE IF EXISTS `alembic_version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `alembic_version` (
  `version_num` varchar(32) NOT NULL,
  PRIMARY KEY (`version_num`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `alembic_version`
--

LOCK TABLES `alembic_version` WRITE;
/*!40000 ALTER TABLE `alembic_version` DISABLE KEYS */;
INSERT INTO `alembic_version` VALUES ('5d7e087a93e9');
/*!40000 ALTER TABLE `alembic_version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `audit_logs`
--

DROP TABLE IF EXISTS `audit_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `timestamp` datetime NOT NULL,
  `username` varchar(100) NOT NULL,
  `action` varchar(50) NOT NULL,
  `table_name` varchar(50) NOT NULL,
  `record_id` int NOT NULL,
  `changes` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `audit_logs`
--

LOCK TABLES `audit_logs` WRITE;
/*!40000 ALTER TABLE `audit_logs` DISABLE KEYS */;
INSERT INTO `audit_logs` VALUES (1,'2024-11-17 18:11:07','engineer1','Обновление','Fire',1,''),(2,'2024-11-18 12:46:28','admin','Обновление','Fire',1,''),(3,'2024-11-18 18:11:40','engineer1','Обновление','Fire',7,'damage_area: 1.00 -> 0.50; damage_not_les: 0.50 -> 0.00'),(4,'2024-11-18 18:17:40','admin','Обновление','Fire',6,'damage_area: 1.00 -> 0.50; damage_not_les: 0.50 -> 0.00'),(5,'2024-11-18 18:18:02','engineer1','Обновление','Fire',7,'damage_area: 0.50 -> 1.00; damage_not_les: 0.00 -> 0.50'),(6,'2024-11-20 11:43:35','engineer1','Обновление','Fire',8,'damage_area: 0.50 -> 1.00; damage_not_les: 0.20 -> 0.70; KPS_flag: True -> False'),(7,'2024-11-20 11:59:34','engineer1','Обновление','Fire',9,'damage_area: 5.00 -> 10.00; damage_les: 1.00 -> 4.00; damage_not_les: 2.00 -> 6.00'),(8,'2024-11-26 07:15:58','engineer1','Обновление','Fire',10,'damage_area: 5.00 -> 10.00; damage_les_verh: 0.00 -> None; damage_not_les: 4.00 -> 6.00; file_path: None -> jpg'),(9,'2024-11-26 16:20:59','engineer1','Обновление','Fire',10,'quarter: 12 -> 5; damage_area: 10.00 -> 15.00'),(10,'2024-11-26 16:29:33','engineer1','Обновление','Fire',10,'allotment: 3 -> 4; damage_area: 15.00 -> 10.00'),(11,'2024-11-26 17:22:53','admin','Удаление','Fire',10,'Удалена запись о пожаре с ID 10'),(12,'2024-11-26 17:28:05','admin','Удаление','Fire',5,'Удалена запись о пожаре с ID 5'),(13,'2024-11-27 11:51:05','engineer1','Обновление','Fire',9,'quarter: 5 -> 5, 4; allotment: 1 -> 1, 18, 20; LO_flag: None -> True; LO_people_count: None -> 5; LO_tecnic_count: None -> 2'),(14,'2024-11-27 12:02:42','engineer3','Обновление','Fire',11,'quarter: 5, 4 -> 5, 4, 7; allotment: 1, 18, 20 -> 1, 18, 20, 22; damage_les_verh: 0.00 -> None; file_path: None -> pngtree-red-fire-icon-vector-png-image_6012850.jpg'),(15,'2024-11-27 12:16:34','engineer3','Обновление','Fire',11,'quarter: 5, 4, 7 -> 5, 4, 7, 10');
/*!40000 ALTER TABLE `audit_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `fires`
--

DROP TABLE IF EXISTS `fires`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `fires` (
  `id` int NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `region` varchar(255) NOT NULL,
  `location` varchar(255) NOT NULL,
  `damage_area` decimal(10,2) DEFAULT NULL,
  `damage_les` decimal(10,2) DEFAULT NULL,
  `damage_les_lesopokryt` decimal(10,2) DEFAULT NULL,
  `damage_les_verh` decimal(10,2) DEFAULT NULL,
  `damage_not_les` decimal(10,2) DEFAULT NULL,
  `APS_flag` tinyint(1) DEFAULT NULL,
  `APS_people_count` int DEFAULT NULL,
  `APS_tecnic_count` int DEFAULT NULL,
  `APS_aircraft_count` int DEFAULT NULL,
  `KPS_flag` tinyint(1) DEFAULT NULL,
  `KPS_people_count` int DEFAULT NULL,
  `KPS_tecnic_count` int DEFAULT NULL,
  `KPS_aircraft_count` int DEFAULT NULL,
  `MIO_flag` tinyint(1) DEFAULT NULL,
  `MIO_people_count` int DEFAULT NULL,
  `MIO_tecnic_count` int DEFAULT NULL,
  `MIO_aircraft_count` int DEFAULT NULL,
  `other_org_flag` tinyint(1) DEFAULT NULL,
  `other_org_people_count` int DEFAULT NULL,
  `other_org_tecnic_count` int DEFAULT NULL,
  `other_org_aircraft_count` int DEFAULT NULL,
  `description` text,
  `file_path` varchar(255) DEFAULT NULL,
  `edited_by_engineer` tinyint(1) DEFAULT NULL,
  `branch` varchar(255) DEFAULT NULL,
  `forestry` varchar(255) DEFAULT NULL,
  `quarter` varchar(255) DEFAULT NULL,
  `allotment` varchar(255) DEFAULT NULL,
  `damage_tenge` int DEFAULT NULL,
  `firefighting_costs` int DEFAULT NULL,
  `LO_flag` tinyint(1) DEFAULT NULL,
  `LO_people_count` int DEFAULT NULL,
  `LO_tecnic_count` int DEFAULT NULL,
  `KPO` int DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `fires`
--

LOCK TABLES `fires` WRITE;
/*!40000 ALTER TABLE `fires` DISABLE KEYS */;
INSERT INTO `fires` VALUES (1,'2024-08-01','Акмолинская область','на территории КГУ УЛХ «Красноборское», квартал 56, выдел 21',1.00,0.02,0.02,0.00,0.00,0,12,6,0,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'загорание сухой травы','2024-10-28_213252.png',1,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(2,'2024-10-08','Акмолинская область','на территории КГУ УЛХ «Букпа» (квартал 89)',15.00,0.83,0.83,0.00,0.00,0,4,1,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'загорание сухой травы и лесной подстилки','24-26.10.2024_.pdf',1,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(3,'2024-10-29','Акмолинская область','на территории КГУ УЛХ «Куйбышевское лесничество» (209 квартал)',7.00,5.00,5.00,0.00,2.00,1,12,4,-1,1,4,1,-2,1,7,2,0,0,NULL,NULL,NULL,'загорание сухой травы и лесной подстилки',NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(4,'2024-10-01','Актюбинская область','ГУ «Актюбинское лесное хозяйство» (Ленинское лесничество, 68 квартал)',10.00,10.00,10.00,0.00,0.00,1,16,4,1,1,8,2,0,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'загорание сухой травы и кустарников',NULL,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(6,'2024-11-18','Акмолинская область','Красноборское',0.50,0.50,0.50,NULL,0.00,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'',NULL,0,'Красноборское','Красноборское','56','21',50000,500,NULL,NULL,NULL,NULL),(7,'2024-11-18','Акмолинская область','Красноборское',1.00,0.50,0.50,NULL,0.50,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'загорание деревьев и лесной подстилки',NULL,0,'Красноборское','Красноборское','56','21',5000,500,NULL,NULL,NULL,NULL),(8,'2024-11-20','Акмолинская область','Степногорское',1.00,0.10,0.10,0.10,0.70,0,NULL,NULL,NULL,0,4,1,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'загорание деревьев и лесной подстилки','08.11-10.11.2024_.pdf',0,'лесхоз 1','второе','2','12',50000,1000,NULL,NULL,NULL,NULL),(9,'2024-11-20','Акмолинская область','Ерейментауское',10.00,4.00,1.00,1.00,6.00,1,4,1,1,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'загорание кустарников и лесной подстилки',NULL,0,'лесхоз 5','первое','5, 4','1, 18, 20',NULL,NULL,1,5,2,NULL),(11,'2024-09-12','Атырауская область','Индерское',10.00,8.00,8.00,NULL,2.00,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'деревья и лесная подстилка','pngtree-red-fire-icon-vector-png-image_6012850.jpg',0,'лесхоз','первое','5, 4, 7, 10','1, 18, 20, 22',14000,1000,1,8,3,NULL),(12,'2024-10-07','Павлодарская область','Баянаульский ГНПП',100.00,50.00,50.00,0.00,50.00,1,NULL,NULL,3,1,40,10,NULL,0,NULL,NULL,NULL,0,NULL,NULL,NULL,'лесная подстилка',NULL,0,'лесхоз','второе','1,2,3,10','11,12,13',NULL,NULL,1,20,5,5);
/*!40000 ALTER TABLE `fires` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(150) NOT NULL,
  `password` varchar(150) NOT NULL,
  `roles` varchar(50) NOT NULL,
  `region` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'admin','pbkdf2:sha256:600000$JHgQXdfw5oo7oB3H$42ab679e9da0d1f6625a8062a0544ce116a4ecbf6ae94cdf517cd81573bfb516','admin','Не указан'),(3,'engineer1','pbkdf2:sha256:600000$BTjMYI7JmU232ntZ$e429ed25738cb8a59209871398612f4322d8a58042bb7f63669af7db75f0196c','engineer','Акмолинская область'),(4,'operator1','pbkdf2:sha256:600000$SbFc4YCKlVFhtBl3$429cb6bc718daa4e129e9eb1832d72380e06eb93961500aa8fa8a651c21be67b','operator','Акмолинская область'),(5,'engineer2','pbkdf2:sha256:600000$xsyk1sUHIzuc3gzl$cc63743fd5aaef228022e3d2f0263ceda0a2f3a7f6992b29bf03a7a60f143357','engineer','Актюбинская область'),(6,'operator2','pbkdf2:sha256:600000$csAkZ5ASg25aijva$62e1620b1cffc9039d5772f65ba1a8e8c707cbf241fc95045ca1b3fcd1b1410f','operator','Актюбинская область'),(7,'analyst','pbkdf2:sha256:600000$cKuaqGL87ch74uKM$322c4d248d16664f2fd7b13b5285b00add07898270884d7ac998a0d4198a6bc0','analyst','Не указан'),(8,'operator3','pbkdf2:sha256:600000$2BkjYFNl5V3KAAUA$cc7220dde417c86c980634fe2c1206c99a288e05904c721b3d7702fc06c2d217','operator','Атырауская область'),(9,'operator4','pbkdf2:sha256:600000$GB4ufViyoPPvl5vJ$329d6cda6e14a928f692bab6d60ce39d1485f1fb52fd7e12d22e25a189f7a642','operator','Алматинская область'),(10,'operator5','pbkdf2:sha256:600000$RO3jUpz3IRPzJIJt$bd36e304dca8fc7a539c38d3df4bf6ab1d8be8ad41f910c1a9144213ac8f5777','operator','Восточно-Казахстанская область'),(11,'operator6','pbkdf2:sha256:600000$9Fc2vKSOxgb9NwaY$f05a7847732675e6729b1f97a0f387b5e187b8b8a4b79b911f2c2d12e56db213','operator','Западно-Казахстанская область'),(12,'operator7','pbkdf2:sha256:600000$Xc9QQQYO2j9XAvw7$85f0e3cdd6d3862621fed32740eb5a11b61d20ce03d768ff88eaf6545877e897','operator','Карагандинская область'),(13,'operator8','pbkdf2:sha256:600000$9NHDRhgnwcvdMWrq$719f8cbbd55f908ebf476c42a649fc52e506d697b8dc2dac348807edde6a169b','operator','Костанайская область'),(14,'operator9','pbkdf2:sha256:600000$EFEF16E7Um9xhzhw$eb3289d21c1d0e3dc9ed616da71a21e4f468968653296864c54b64e1d001ceeb','operator','Кызылординская область'),(15,'operator10','pbkdf2:sha256:600000$d0gYXCXCDbOwHx0L$3e60707b231bf03b0ebf41a613795088d4adf4eb0b57421a9174fa7995a2903e','operator','Жамбылская область'),(16,'operator11','pbkdf2:sha256:600000$n0sMXT8iaD47zF7W$096c3b2c47c89c8d2369da03db0584fb4905009ad92a7c595c437701b2bada95','operator','Мангыстауская  область'),(17,'operator12','pbkdf2:sha256:600000$ueJTNp4S5QzxVyHT$5fd9d81504d6efedb4f3364d2b776b3b79e79c0d7925c6b4cc0e563b81cafb65','operator','Павлодарская область'),(18,'operator13','pbkdf2:sha256:600000$jllGZoLg2K7t1sbI$80e1d50d636a66a2574ef807f329ea4136a24f2d9052c53e3111caf566d07c42','operator','Северо-Казахстанская область'),(19,'operator14','pbkdf2:sha256:600000$n0BgtQoAeBIfrExK$0b690d3eb631061f1021711abd5af1cc82e622aa2f3a0c40bdb79bae528bfeb7','operator','Туркестанская область'),(20,'operator15','pbkdf2:sha256:600000$USOjhtWQyuwcK6bK$272110ee94e1d2df52079d981ecd51e89cfa18aae64075c247f02a4e96ed2988','operator','г. Астана'),(21,'operator16','pbkdf2:sha256:600000$4AZuXof1u2soK1Ai$7d94d1d71de5e1996c0d6a3b676b1b697a199a906b9d2f025cdd15ffa5f0dc9d','operator','г. Алматы'),(22,'operator17','pbkdf2:sha256:600000$mUY4osD9O9qMDicw$912daeeb65549a8642652fcde7efd417200a820928b6ed32cce9ebd3e3078a90','operator','г. Шымкент'),(23,'operator18','pbkdf2:sha256:600000$OD6SIccRQo6LTebC$ef67dd89e3d4edeca1406946f7bb14a9d58156dc0f2f03c2c951d00ee72587e3','operator','Область Абай'),(24,'operator19','pbkdf2:sha256:600000$n1NhmQlYXdvLStc6$ebb883c2585701cc8aac398555374d6af4f302e85ffaade7ae8ce42d7807b520','operator','Область Жетысу'),(25,'operator20','pbkdf2:sha256:600000$fbV8wLf7ZN8rrlii$4354e34ff369ffacda5a1b7b8a225ba59e578e2554f81ccd935ff16703cf0873','operator','Область Улытау'),(26,'engineer3','pbkdf2:sha256:600000$FU93DK5SY90tQHl1$0a1b3c6126db44e6d874981340ac02de2994b5555db6c2a191ec0bab99a406d3','engineer','Атырауская область'),(27,'engineer4','pbkdf2:sha256:600000$Q3THIJjju4mEFmbM$5b1e7340a07094652179be3401c14aa932d05f85df04d408ef572ea01f4c1bb3','engineer','Алматинская область'),(28,'engineer5','pbkdf2:sha256:600000$eJ6LEkwAmBLIrNSk$81a15ccf1c8e59961de77502d95ed28b9088a01b83c0195ad8ec25b2e3e6c5fe','engineer','Восточно-Казахстанская область'),(29,'engineer6','pbkdf2:sha256:600000$ox2qU4ZYY45ErWFx$889724c1efe7e77778b8ef3fdc0ac0806b76b1950a8fea68ed0e8e26609b8e04','engineer','Западно-Казахстанская область'),(30,'engineer7','pbkdf2:sha256:600000$HAcv87iWVFqISxfg$90bb694ba8c393424b7bf6f3567cc045b8015c7b9d37419c064ca4904bc751e2','engineer','Карагандинская область'),(31,'engineer8','pbkdf2:sha256:600000$j2T4ntvgqJLzxObW$889a619c180b93290cca576f4da0a0acecfbd4bedd087878fb39c3e820687189','engineer','Костанайская область'),(32,'engineer9','pbkdf2:sha256:600000$QfouXA5HxcSQCg4Q$6e8c86152e637fd50ab2a51abfa10931b23391d713dc90e4e16dc4786c7cf8d9','engineer','Кызылординская область'),(33,'engineer10','pbkdf2:sha256:600000$k1fQTlkkvXgXfKj7$129423b21f73a4426ca56fe37906f78993891c16e557ac8769017e85caf54569','engineer','Жамбылская область'),(34,'engineer11','pbkdf2:sha256:600000$bHafkZBVX0AhHdzR$2a406efbc71cd74b70ec1e0d5f1ead10dc21919ba4f4cb39fbb0e8f54ad3737b','engineer','Мангыстауская  область'),(35,'engineer12','pbkdf2:sha256:600000$qHLC2zqGhb6fFgwb$d8929c7c6a97357ae7f695e6183d0cc45bb0131e2fe1b7f8d72363459886fcb6','engineer','Павлодарская область'),(36,'engineer13','pbkdf2:sha256:600000$fyCXHAeG63q1bK5c$3dfed0e8b1c1eee6430853034386e08eaca0d23d10a33424d6f8c5b726805938','engineer','Северо-Казахстанская область'),(37,'engineer14','pbkdf2:sha256:600000$835Wf584bZ2v7DlK$7c7e8b91fc9929afb94931c42927d5a768f62dbb7d537491cabf33c85cf6f333','engineer','Туркестанская область'),(38,'engineer15','pbkdf2:sha256:600000$6VqkEl39uORweQOj$5c7084dfcf4c7a927b5f185bc7b29c4c12e4ed3530463297ec094d92188e9e00','engineer','г. Астана'),(39,'engineer16','pbkdf2:sha256:600000$SrKBiBJmzJGIlNs1$68b61177cf330c881ed6daf7882be7d938a15084de53746991f4d5bf1e859125','engineer','г. Алматы'),(40,'engineer17','pbkdf2:sha256:600000$gIe3b1i73aNTh6Q7$a4cc46ad92a48d043e1953e2426f32ba243854b4212ddcd3e9f0288ecefbd189','engineer','г. Шымкент'),(41,'engineer18','pbkdf2:sha256:600000$fbvRja8LRO9x2JRe$f03da1b68c98df3571029437b5f4d0ac142042a4cf33eb270c1f66b985f6a2dd','engineer','Область Абай'),(42,'engineer19','pbkdf2:sha256:600000$AhdU9Z6QlkA2pOjJ$86c0de7473249161aae580d9c617033dc922c8252f0f8dfb8f0a02063e688c6f','engineer','Область Жетысу'),(43,'engineer20','pbkdf2:sha256:600000$DwkZYaZGjgXjmUfU$cc4050e19f12f24929930c820b89b11b884645dbd8c428e096b4fc4a88c61e3a','engineer','Область Улытау'),(44,'admin1','pbkdf2:sha256:600000$mPIUOVLWuKCy3gNL$b11ba252e9b3118a8499e9a00b43bc2827c1f58085dc71978e53b89336af70f1','admin','Не указан');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-11-27 17:33:06
