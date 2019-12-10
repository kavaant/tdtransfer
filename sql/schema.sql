CREATE TABLE `account` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `login` varchar(40) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `apikey` varchar(255) DEFAULT NULL,
  `apbnr` int(8) DEFAULT NULL,
  PRIMARY KEY (`id`)
)

CREATE TABLE `filehashes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` datetime DEFAULT NULL,
  `hash` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
)

CREATE TABLE `log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) DEFAULT NULL,
  `datum` datetime DEFAULT NULL,
  `ip` varchar(20) DEFAULT NULL,
  `function` varchar(30) DEFAULT NULL,
  `exitcode` int(11) DEFAULT NULL,
  `subcode` int(11) DEFAULT NULL,
  `msg` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
)
