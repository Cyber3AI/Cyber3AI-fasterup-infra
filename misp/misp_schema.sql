/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19  Distrib 10.11.14-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: misp
-- ------------------------------------------------------
-- Server version	10.11.14-MariaDB-0+deb12u2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `access_logs`
--

DROP TABLE IF EXISTS `access_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `access_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created` datetime(4) NOT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `authkey_id` int(11) DEFAULT NULL,
  `ip` varbinary(16) DEFAULT NULL,
  `request_method` tinyint(4) NOT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `request_id` varchar(255) DEFAULT NULL,
  `controller` varchar(20) NOT NULL,
  `action` varchar(191) NOT NULL,
  `url` varchar(255) NOT NULL,
  `request` blob DEFAULT NULL,
  `response_code` smallint(6) NOT NULL,
  `memory_usage` int(11) NOT NULL,
  `duration` int(11) NOT NULL,
  `query_count` int(11) NOT NULL,
  `query_log` blob DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=60 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `admin_settings`
--

DROP TABLE IF EXISTS `admin_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `admin_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `value` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `setting` (`setting`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `allowedlist`
--

DROP TABLE IF EXISTS `allowedlist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `allowedlist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `analyst_data_blocklists`
--

DROP TABLE IF EXISTS `analyst_data_blocklists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `analyst_data_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `analyst_data_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `analyst_data_info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `analyst_data_orgc` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `analyst_data_uuid` (`analyst_data_uuid`),
  KEY `analyst_data_orgc` (`analyst_data_orgc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attachment_scans`
--

DROP TABLE IF EXISTS `attachment_scans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `attachment_scans` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `infected` tinyint(1) NOT NULL,
  `malware_name` varchar(191) DEFAULT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index` (`type`,`attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attr_value_counts`
--

DROP TABLE IF EXISTS `attr_value_counts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `attr_value_counts` (
  `value` varchar(64) NOT NULL,
  `cnt_v1` bigint(20) unsigned NOT NULL DEFAULT 0,
  `cnt_v2` bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attribute_tags`
--

DROP TABLE IF EXISTS `attribute_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `attribute_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `relationship_type` varchar(191) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `event_id` (`event_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4941618 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attributes`
--

DROP TABLE IF EXISTS `attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `object_id` int(11) NOT NULL DEFAULT 0,
  `object_relation` varchar(255) DEFAULT NULL,
  `category` varchar(255) NOT NULL,
  `type` varchar(100) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `value1` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `value2` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `uuid` varchar(40) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `first_seen` bigint(20) DEFAULT NULL,
  `last_seen` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `event_id` (`event_id`),
  KEY `object_id` (`object_id`),
  KEY `object_relation` (`object_relation`),
  KEY `value1` (`value1`(255)),
  KEY `value2` (`value2`(255)),
  KEY `type` (`type`),
  KEY `category` (`category`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `first_seen` (`first_seen`),
  KEY `last_seen` (`last_seen`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB AUTO_INCREMENT=2929007 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `audit_logs`
--

DROP TABLE IF EXISTS `audit_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `created` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `authkey_id` int(11) DEFAULT NULL,
  `ip` varbinary(16) DEFAULT NULL,
  `request_type` tinyint(4) NOT NULL,
  `request_id` varchar(255) DEFAULT NULL,
  `action` varchar(20) NOT NULL,
  `model` varchar(80) NOT NULL,
  `model_id` int(11) NOT NULL,
  `model_title` text DEFAULT NULL,
  `event_id` int(11) DEFAULT NULL,
  `change` blob DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `model_id` (`model_id`)
) ENGINE=InnoDB AUTO_INCREMENT=8056627 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `auth_keys`
--

DROP TABLE IF EXISTS `auth_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_keys` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) NOT NULL,
  `authkey` varchar(72) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authkey_start` varchar(4) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authkey_end` varchar(4) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` int(10) unsigned NOT NULL,
  `expiration` int(10) unsigned NOT NULL,
  `read_only` tinyint(1) NOT NULL DEFAULT 0,
  `user_id` int(10) unsigned NOT NULL,
  `comment` text DEFAULT NULL,
  `allowed_ips` text DEFAULT NULL,
  `unique_ips` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `authkey_start` (`authkey_start`),
  KEY `authkey_end` (`authkey_end`),
  KEY `created` (`created`),
  KEY `expiration` (`expiration`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `bookmarks`
--

DROP TABLE IF EXISTS `bookmarks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `bookmarks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(10) unsigned NOT NULL,
  `org_id` int(10) unsigned NOT NULL,
  `name` varchar(191) NOT NULL,
  `url` text NOT NULL,
  `exposed_to_org` tinyint(1) NOT NULL DEFAULT 0,
  `comment` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `org_id` (`org_id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `bruteforces`
--

DROP TABLE IF EXISTS `bruteforces`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `bruteforces` (
  `ip` varchar(255) NOT NULL,
  `username` varchar(255) NOT NULL,
  `expire` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cake_sessions`
--

DROP TABLE IF EXISTS `cake_sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cake_sessions` (
  `id` varchar(255) NOT NULL DEFAULT '',
  `data` text NOT NULL,
  `expires` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cerebrates`
--

DROP TABLE IF EXISTS `cerebrates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cerebrates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(191) NOT NULL,
  `url` varchar(255) NOT NULL,
  `authkey` varbinary(255) NOT NULL,
  `open` tinyint(1) DEFAULT 0,
  `org_id` int(11) NOT NULL,
  `pull_orgs` tinyint(1) DEFAULT 0,
  `pull_sharing_groups` tinyint(1) DEFAULT 0,
  `self_signed` tinyint(1) DEFAULT 0,
  `cert_file` varchar(255) DEFAULT NULL,
  `client_cert_file` varchar(255) DEFAULT NULL,
  `internal` tinyint(1) NOT NULL DEFAULT 0,
  `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
  `description` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `url` (`url`),
  KEY `org_id` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `collection_elements`
--

DROP TABLE IF EXISTS `collection_elements`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `collection_elements` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `element_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `element_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `collection_id` int(10) unsigned NOT NULL,
  `description` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  UNIQUE KEY `unique_element` (`element_uuid`,`collection_id`),
  KEY `element_uuid` (`element_uuid`),
  KEY `element_type` (`element_type`),
  KEY `collection_id` (`collection_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `collections`
--

DROP TABLE IF EXISTS `collections`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `collections` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `org_id` int(10) unsigned NOT NULL,
  `orgc_id` int(10) unsigned NOT NULL,
  `user_id` int(10) unsigned NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `name` varchar(191) NOT NULL,
  `type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `description` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `type` (`type`),
  KEY `org_id` (`org_id`),
  KEY `orgc_id` (`orgc_id`),
  KEY `user_id` (`user_id`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `correlation_exclusions`
--

DROP TABLE IF EXISTS `correlation_exclusions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `correlation_exclusions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text NOT NULL,
  `from_json` tinyint(1) DEFAULT 0,
  `comment` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `value` (`value`(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `correlation_rules`
--

DROP TABLE IF EXISTS `correlation_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `correlation_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `name` varchar(191) NOT NULL,
  `comment` text DEFAULT NULL,
  `selector_type` varchar(40) NOT NULL,
  `selector_list` text DEFAULT NULL,
  `created` int(11) NOT NULL DEFAULT unix_timestamp(),
  `timestamp` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `selector_type` (`selector_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `correlation_values`
--

DROP TABLE IF EXISTS `correlation_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `correlation_values` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `value` varchar(191) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `value` (`value`)
) ENGINE=InnoDB AUTO_INCREMENT=94430 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `correlations`
--

DROP TABLE IF EXISTS `correlations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `1_attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `a_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(11) NOT NULL,
  `a_sharing_group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `1_attribute_id` (`1_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `cryptographic_keys`
--

DROP TABLE IF EXISTS `cryptographic_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cryptographic_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `type` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `parent_id` int(11) NOT NULL,
  `parent_type` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `key_data` text DEFAULT NULL,
  `revoked` tinyint(1) NOT NULL DEFAULT 0,
  `fingerprint` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `type` (`type`),
  KEY `parent_id` (`parent_id`),
  KEY `parent_type` (`parent_type`),
  KEY `fingerprint` (`fingerprint`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dashboards`
--

DROP TABLE IF EXISTS `dashboards`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `dashboards` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `description` text DEFAULT NULL,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  `selectable` tinyint(1) NOT NULL DEFAULT 0,
  `user_id` int(11) NOT NULL DEFAULT 0,
  `restrict_to_org_id` int(11) NOT NULL DEFAULT 0,
  `restrict_to_role_id` int(11) NOT NULL DEFAULT 0,
  `restrict_to_permission_flag` varchar(191) NOT NULL DEFAULT '',
  `value` text DEFAULT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `user_id` (`user_id`),
  KEY `restrict_to_org_id` (`restrict_to_org_id`),
  KEY `restrict_to_permission_flag` (`restrict_to_permission_flag`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `decaying_model_mappings`
--

DROP TABLE IF EXISTS `decaying_model_mappings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `decaying_model_mappings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `model_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `model_id` (`model_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `decaying_models`
--

DROP TABLE IF EXISTS `decaying_models`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `decaying_models` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `parameters` text DEFAULT NULL,
  `attribute_types` text DEFAULT NULL,
  `description` text DEFAULT NULL,
  `org_id` int(11) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `all_orgs` tinyint(1) NOT NULL DEFAULT 1,
  `ref` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `formula` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `version` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT '',
  `default` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `enabled` (`enabled`),
  KEY `all_orgs` (`all_orgs`),
  KEY `version` (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `default_correlations`
--

DROP TABLE IF EXISTS `default_correlations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `default_correlations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `attribute_id` int(10) unsigned NOT NULL,
  `object_id` int(10) unsigned NOT NULL,
  `event_id` int(10) unsigned NOT NULL,
  `org_id` int(10) unsigned NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `object_distribution` tinyint(4) NOT NULL,
  `event_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `object_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `event_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `1_attribute_id` int(10) unsigned NOT NULL,
  `1_object_id` int(10) unsigned NOT NULL,
  `1_event_id` int(10) unsigned NOT NULL,
  `1_org_id` int(10) unsigned NOT NULL,
  `1_distribution` tinyint(4) NOT NULL,
  `1_object_distribution` tinyint(4) NOT NULL,
  `1_event_distribution` tinyint(4) NOT NULL,
  `1_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `1_object_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `1_event_sharing_group_id` int(10) unsigned NOT NULL DEFAULT 0,
  `value_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_correlation` (`attribute_id`,`1_attribute_id`,`value_id`),
  KEY `event_id` (`event_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `object_id` (`object_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `1_attribute_id` (`1_attribute_id`),
  KEY `1_object_id` (`1_object_id`),
  KEY `value_id` (`value_id`)
) ENGINE=InnoDB AUTO_INCREMENT=215152 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_blocklists`
--

DROP TABLE IF EXISTS `event_blocklists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `event_info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `event_orgc` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `event_uuid` (`event_uuid`),
  KEY `event_orgc` (`event_orgc`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_delegations`
--

DROP TABLE IF EXISTS `event_delegations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_delegations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `requester_org_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `message` text DEFAULT NULL,
  `distribution` tinyint(4) NOT NULL DEFAULT -1,
  `sharing_group_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `event_id` (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_graph`
--

DROP TABLE IF EXISTS `event_graph`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_graph` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `network_name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `network_json` mediumtext NOT NULL,
  `preview_img` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `user_id` (`user_id`),
  KEY `org_id` (`org_id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_locks`
--

DROP TABLE IF EXISTS `event_locks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_locks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `user_id` (`user_id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_report_tags`
--

DROP TABLE IF EXISTS `event_report_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_report_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_report_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `relationship_type` varchar(191) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `event_report_id` (`event_report_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_report_template_variables`
--

DROP TABLE IF EXISTS `event_report_template_variables`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_report_template_variables` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(191) NOT NULL,
  `value` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_reports`
--

DROP TABLE IF EXISTS `event_reports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_reports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `event_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `content` mediumtext DEFAULT NULL,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `timestamp` int(11) NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `event_id` (`event_id`)
) ENGINE=InnoDB AUTO_INCREMENT=135 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `event_tags`
--

DROP TABLE IF EXISTS `event_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `event_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `relationship_type` varchar(191) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB AUTO_INCREMENT=14349 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `events`
--

DROP TABLE IF EXISTS `events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `events` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `date` date NOT NULL,
  `info` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_id` int(11) NOT NULL,
  `uuid` varchar(40) NOT NULL,
  `published` tinyint(1) NOT NULL DEFAULT 0,
  `analysis` tinyint(4) NOT NULL,
  `attribute_count` int(11) unsigned DEFAULT 0,
  `orgc_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL,
  `proposal_email_lock` tinyint(1) NOT NULL DEFAULT 0,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `threat_level_id` int(11) NOT NULL,
  `publish_timestamp` int(11) NOT NULL DEFAULT 0,
  `sighting_timestamp` int(11) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `extends_uuid` varchar(40) DEFAULT '',
  `protected` tinyint(1) DEFAULT NULL,
  `first_publication` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `info` (`info`(255)),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `org_id` (`org_id`),
  KEY `orgc_id` (`orgc_id`),
  KEY `extends_uuid` (`extends_uuid`),
  KEY `first_publication` (`first_publication`)
) ENGINE=InnoDB AUTO_INCREMENT=4067 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `favourite_tags`
--

DROP TABLE IF EXISTS `favourite_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `favourite_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tag_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `feeds`
--

DROP TABLE IF EXISTS `feeds`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `feeds` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `provider` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `url` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `rules` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) NOT NULL DEFAULT 0,
  `tag_id` int(11) NOT NULL DEFAULT 0,
  `default` tinyint(1) DEFAULT 0,
  `source_format` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT 'misp',
  `fixed_event` tinyint(1) NOT NULL DEFAULT 0,
  `delta_merge` tinyint(1) NOT NULL DEFAULT 0,
  `event_id` int(11) NOT NULL DEFAULT 0,
  `publish` tinyint(1) NOT NULL DEFAULT 0,
  `override_ids` tinyint(1) NOT NULL DEFAULT 0,
  `settings` text DEFAULT NULL,
  `input_source` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT 'network',
  `delete_local_file` tinyint(1) DEFAULT 0,
  `lookup_visible` tinyint(1) DEFAULT 0,
  `headers` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `caching_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `force_to_ids` tinyint(1) NOT NULL DEFAULT 0,
  `orgc_id` int(11) NOT NULL DEFAULT 0,
  `tag_collection_id` int(11) NOT NULL DEFAULT 0,
  `lock_events` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `input_source` (`input_source`),
  KEY `orgc_id` (`orgc_id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `fuzzy_correlate_ssdeep`
--

DROP TABLE IF EXISTS `fuzzy_correlate_ssdeep`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `fuzzy_correlate_ssdeep` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `chunk` varchar(12) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `chunk` (`chunk`),
  KEY `attribute_id` (`attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `galaxies`
--

DROP TABLE IF EXISTS `galaxies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `galaxies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL DEFAULT '',
  `type` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `version` varchar(255) NOT NULL,
  `icon` varchar(255) NOT NULL DEFAULT '',
  `namespace` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT 'misp',
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `local_only` tinyint(1) NOT NULL DEFAULT 0,
  `kill_chain_order` text DEFAULT NULL,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  `org_id` int(10) unsigned NOT NULL,
  `orgc_id` int(10) unsigned NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `type` (`type`),
  KEY `namespace` (`namespace`)
) ENGINE=InnoDB AUTO_INCREMENT=113 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `galaxy_cluster_blocklists`
--

DROP TABLE IF EXISTS `galaxy_cluster_blocklists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `galaxy_cluster_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cluster_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `cluster_info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `cluster_orgc` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `cluster_uuid` (`cluster_uuid`),
  KEY `cluster_orgc` (`cluster_orgc`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `galaxy_cluster_relation_tags`
--

DROP TABLE IF EXISTS `galaxy_cluster_relation_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `galaxy_cluster_relation_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_relation_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `galaxy_cluster_relation_id` (`galaxy_cluster_relation_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18865 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `galaxy_cluster_relations`
--

DROP TABLE IF EXISTS `galaxy_cluster_relations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `galaxy_cluster_relations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_id` int(11) NOT NULL,
  `referenced_galaxy_cluster_id` int(11) NOT NULL,
  `referenced_galaxy_cluster_uuid` varchar(255) NOT NULL,
  `referenced_galaxy_cluster_type` text NOT NULL,
  `galaxy_cluster_uuid` varchar(40) NOT NULL,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `galaxy_cluster_id` (`galaxy_cluster_id`),
  KEY `referenced_galaxy_cluster_id` (`referenced_galaxy_cluster_id`),
  KEY `referenced_galaxy_cluster_type` (`referenced_galaxy_cluster_type`(255)),
  KEY `galaxy_cluster_uuid` (`galaxy_cluster_uuid`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `default` (`default`)
) ENGINE=InnoDB AUTO_INCREMENT=60192 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `galaxy_clusters`
--

DROP TABLE IF EXISTS `galaxy_clusters`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `galaxy_clusters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(255) NOT NULL DEFAULT '',
  `collection_uuid` varchar(255) NOT NULL,
  `type` varchar(255) NOT NULL,
  `value` text NOT NULL,
  `tag_name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL DEFAULT '',
  `description` text NOT NULL,
  `galaxy_id` int(11) NOT NULL,
  `source` varchar(255) NOT NULL DEFAULT '',
  `authors` text NOT NULL,
  `version` int(11) DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `org_id` int(11) NOT NULL,
  `orgc_id` int(11) NOT NULL,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `extends_uuid` varchar(40) DEFAULT '',
  `extends_version` int(11) DEFAULT 0,
  `published` tinyint(1) NOT NULL DEFAULT 0,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `value` (`value`(255)),
  KEY `uuid` (`uuid`),
  KEY `collection_uuid` (`collection_uuid`),
  KEY `galaxy_id` (`galaxy_id`),
  KEY `version` (`version`),
  KEY `tag_name` (`tag_name`),
  KEY `type` (`type`),
  KEY `org_id` (`org_id`),
  KEY `orgc_id` (`orgc_id`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `extends_uuid` (`extends_uuid`),
  KEY `extends_version` (`extends_version`),
  KEY `default` (`default`)
) ENGINE=InnoDB AUTO_INCREMENT=49301 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `galaxy_elements`
--

DROP TABLE IF EXISTS `galaxy_elements`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `galaxy_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `galaxy_cluster_id` int(11) NOT NULL,
  `key` varchar(255) NOT NULL DEFAULT '',
  `value` text NOT NULL,
  PRIMARY KEY (`id`),
  KEY `key` (`key`),
  KEY `value` (`value`(255)),
  KEY `galaxy_cluster_id` (`galaxy_cluster_id`)
) ENGINE=InnoDB AUTO_INCREMENT=312036 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `inbox`
--

DROP TABLE IF EXISTS `inbox`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `inbox` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `title` varchar(191) NOT NULL,
  `type` varchar(191) NOT NULL,
  `ip` varchar(191) NOT NULL,
  `user_agent` text DEFAULT NULL,
  `user_agent_sha256` varchar(64) NOT NULL,
  `comment` text DEFAULT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `timestamp` int(11) NOT NULL,
  `store_as_file` tinyint(1) NOT NULL DEFAULT 0,
  `data` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `title` (`title`),
  KEY `type` (`type`),
  KEY `user_agent_sha256` (`user_agent_sha256`),
  KEY `ip` (`ip`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `jobs`
--

DROP TABLE IF EXISTS `jobs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `jobs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `worker` varchar(32) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `job_type` varchar(32) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `job_input` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `status` tinyint(4) NOT NULL DEFAULT 0,
  `retries` int(11) NOT NULL DEFAULT 0,
  `message` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `progress` int(11) NOT NULL DEFAULT 0,
  `org_id` int(11) NOT NULL DEFAULT 0,
  `process_id` varchar(36) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4657 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `logs`
--

DROP TABLE IF EXISTS `logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` text DEFAULT NULL,
  `created` datetime NOT NULL,
  `model` varchar(80) NOT NULL,
  `model_id` int(11) NOT NULL,
  `action` varchar(20) NOT NULL,
  `user_id` int(11) NOT NULL,
  `change` text DEFAULT NULL,
  `email` varchar(255) NOT NULL DEFAULT '',
  `org` varchar(255) NOT NULL DEFAULT '',
  `description` text DEFAULT NULL,
  `ip` varchar(45) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1532 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `news`
--

DROP TABLE IF EXISTS `news`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `news` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `title` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `date_created` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `no_acl_correlations`
--

DROP TABLE IF EXISTS `no_acl_correlations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `no_acl_correlations` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `attribute_id` int(10) unsigned NOT NULL,
  `1_attribute_id` int(10) unsigned NOT NULL,
  `event_id` int(10) unsigned NOT NULL,
  `1_event_id` int(10) unsigned NOT NULL,
  `value_id` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_correlation` (`attribute_id`,`1_attribute_id`,`value_id`),
  KEY `event_id` (`event_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `1_attribute_id` (`1_attribute_id`),
  KEY `value_id` (`value_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `notes`
--

DROP TABLE IF EXISTS `notes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `notes` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authors` text DEFAULT NULL,
  `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `note` mediumtext DEFAULT NULL,
  `language` varchar(16) DEFAULT 'en',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_uuid` (`object_uuid`),
  KEY `object_type` (`object_type`),
  KEY `org_uuid` (`org_uuid`),
  KEY `orgc_uuid` (`orgc_uuid`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `noticelist_entries`
--

DROP TABLE IF EXISTS `noticelist_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `noticelist_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `noticelist_id` int(11) NOT NULL,
  `data` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `noticelist_id` (`noticelist_id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `noticelists`
--

DROP TABLE IF EXISTS `noticelists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `noticelists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `expanded_name` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `ref` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `geographical_area` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `version` int(11) NOT NULL DEFAULT 1,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `geographical_area` (`geographical_area`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `notification_logs`
--

DROP TABLE IF EXISTS `notification_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `notification_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `type` varchar(255) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `object_references`
--

DROP TABLE IF EXISTS `object_references`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `object_references` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `object_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `source_uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `referenced_uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `referenced_id` int(11) NOT NULL,
  `referenced_type` int(11) NOT NULL DEFAULT 0,
  `relationship_type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_id` (`object_id`),
  KEY `referenced_id` (`referenced_id`),
  KEY `event_id` (`event_id`)
) ENGINE=InnoDB AUTO_INCREMENT=10708 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `object_relationships`
--

DROP TABLE IF EXISTS `object_relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `object_relationships` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `version` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `format` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `highlighted` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=314 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `object_template_elements`
--

DROP TABLE IF EXISTS `object_template_elements`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `object_template_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `object_template_id` int(11) NOT NULL,
  `object_relation` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `ui-priority` int(11) NOT NULL,
  `categories` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `sane_default` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `values_list` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `disable_correlation` tinyint(1) DEFAULT NULL,
  `multiple` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `object_relation` (`object_relation`),
  KEY `type` (`type`),
  KEY `object_template_id` (`object_template_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5605 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `object_templates`
--

DROP TABLE IF EXISTS `object_templates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `object_templates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `meta-category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `version` int(11) NOT NULL,
  `requirements` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `fixed` tinyint(1) NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `org_id` (`org_id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `meta-category` (`meta-category`)
) ENGINE=InnoDB AUTO_INCREMENT=389 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `objects`
--

DROP TABLE IF EXISTS `objects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `objects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `meta-category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `template_uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `template_version` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `distribution` tinyint(4) NOT NULL DEFAULT 0,
  `sharing_group_id` int(11) DEFAULT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `first_seen` bigint(20) DEFAULT NULL,
  `last_seen` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `template_uuid` (`template_uuid`),
  KEY `template_version` (`template_version`),
  KEY `meta-category` (`meta-category`),
  KEY `event_id` (`event_id`),
  KEY `timestamp` (`timestamp`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `first_seen` (`first_seen`),
  KEY `last_seen` (`last_seen`)
) ENGINE=InnoDB AUTO_INCREMENT=23716 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `opinions`
--

DROP TABLE IF EXISTS `opinions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `opinions` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authors` text DEFAULT NULL,
  `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `opinion` int(10) unsigned DEFAULT NULL,
  `comment` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_uuid` (`object_uuid`),
  KEY `object_type` (`object_type`),
  KEY `org_uuid` (`org_uuid`),
  KEY `orgc_uuid` (`orgc_uuid`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `opinion` (`opinion`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `org_blocklists`
--

DROP TABLE IF EXISTS `org_blocklists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `org_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `org_name` varchar(255) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `org_uuid` (`org_uuid`),
  KEY `org_name` (`org_name`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `organisations`
--

DROP TABLE IF EXISTS `organisations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `organisations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `description` text DEFAULT NULL,
  `type` varchar(255) NOT NULL DEFAULT '',
  `nationality` varchar(255) NOT NULL DEFAULT '',
  `sector` varchar(255) NOT NULL DEFAULT '',
  `created_by` int(11) NOT NULL DEFAULT 0,
  `uuid` varchar(40) DEFAULT NULL,
  `contacts` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `local` tinyint(1) NOT NULL DEFAULT 0,
  `restricted_to_domain` text DEFAULT NULL,
  `landingpage` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  UNIQUE KEY `uuid` (`uuid`)
) ENGINE=InnoDB AUTO_INCREMENT=34 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `over_correlating_values`
--

DROP TABLE IF EXISTS `over_correlating_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `over_correlating_values` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `value` varchar(191) NOT NULL,
  `occurrence` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `value` (`value`),
  KEY `occurrence` (`occurrence`)
) ENGINE=InnoDB AUTO_INCREMENT=254 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `posts`
--

DROP TABLE IF EXISTS `posts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `posts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `user_id` int(11) NOT NULL,
  `contents` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `post_id` int(11) NOT NULL DEFAULT 0,
  `thread_id` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `post_id` (`post_id`),
  KEY `thread_id` (`thread_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `regexp`
--

DROP TABLE IF EXISTS `regexp`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `regexp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `regexp` varchar(255) NOT NULL,
  `replacement` varchar(255) NOT NULL,
  `type` varchar(100) NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `relationships`
--

DROP TABLE IF EXISTS `relationships`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `relationships` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `authors` text DEFAULT NULL,
  `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(10) unsigned DEFAULT NULL,
  `locked` tinyint(1) NOT NULL DEFAULT 0,
  `relationship_type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `related_object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `related_object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `object_uuid` (`object_uuid`),
  KEY `object_type` (`object_type`),
  KEY `org_uuid` (`org_uuid`),
  KEY `orgc_uuid` (`orgc_uuid`),
  KEY `distribution` (`distribution`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `relationship_type` (`relationship_type`),
  KEY `related_object_uuid` (`related_object_uuid`),
  KEY `related_object_type` (`related_object_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rest_client_histories`
--

DROP TABLE IF EXISTS `rest_client_histories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `rest_client_histories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `headers` text DEFAULT NULL,
  `body` text DEFAULT NULL,
  `url` text DEFAULT NULL,
  `http_method` varchar(255) DEFAULT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `use_full_path` tinyint(1) DEFAULT 0,
  `show_result` tinyint(1) DEFAULT 0,
  `skip_ssl` tinyint(1) DEFAULT 0,
  `outcome` int(11) NOT NULL,
  `bookmark` tinyint(1) NOT NULL DEFAULT 0,
  `bookmark_name` varchar(255) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `user_id` (`user_id`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `roles`
--

DROP TABLE IF EXISTS `roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `created` datetime DEFAULT NULL,
  `modified` datetime DEFAULT NULL,
  `perm_add` tinyint(1) DEFAULT NULL,
  `perm_modify` tinyint(1) DEFAULT NULL,
  `perm_modify_org` tinyint(1) DEFAULT NULL,
  `perm_publish` tinyint(1) DEFAULT NULL,
  `perm_delegate` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sync` tinyint(1) DEFAULT NULL,
  `perm_admin` tinyint(1) DEFAULT NULL,
  `perm_audit` tinyint(1) DEFAULT NULL,
  `perm_full` tinyint(1) DEFAULT NULL,
  `perm_auth` tinyint(1) NOT NULL DEFAULT 0,
  `perm_site_admin` tinyint(1) NOT NULL DEFAULT 0,
  `perm_regexp_access` tinyint(1) NOT NULL DEFAULT 0,
  `perm_tagger` tinyint(1) NOT NULL DEFAULT 0,
  `perm_template` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sharing_group` tinyint(1) NOT NULL DEFAULT 0,
  `perm_tag_editor` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sighting` tinyint(1) NOT NULL DEFAULT 0,
  `perm_object_template` tinyint(1) NOT NULL DEFAULT 0,
  `default_role` tinyint(1) NOT NULL DEFAULT 0,
  `memory_limit` varchar(255) DEFAULT '',
  `max_execution_time` varchar(255) DEFAULT '',
  `restricted_to_site_admin` tinyint(1) NOT NULL DEFAULT 0,
  `perm_publish_zmq` tinyint(1) NOT NULL DEFAULT 0,
  `perm_publish_kafka` tinyint(1) NOT NULL DEFAULT 0,
  `perm_decaying` tinyint(1) NOT NULL DEFAULT 0,
  `enforce_rate_limit` tinyint(1) NOT NULL DEFAULT 0,
  `rate_limit_count` int(11) NOT NULL DEFAULT 0,
  `perm_galaxy_editor` tinyint(1) NOT NULL DEFAULT 0,
  `perm_warninglist` tinyint(1) NOT NULL DEFAULT 0,
  `perm_view_feed_correlations` tinyint(1) NOT NULL DEFAULT 0,
  `perm_analyst_data` tinyint(1) NOT NULL DEFAULT 0,
  `perm_skip_otp` tinyint(1) NOT NULL DEFAULT 0,
  `perm_server_sign` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sync_internal` tinyint(1) NOT NULL DEFAULT 0,
  `perm_sync_authoritative` tinyint(1) NOT NULL DEFAULT 0,
  `restsearch_limit_result` int(11) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scheduled_tasks`
--

DROP TABLE IF EXISTS `scheduled_tasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `scheduled_tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(100) NOT NULL,
  `timer` int(11) NOT NULL,
  `last_job_id` int(11) DEFAULT NULL,
  `description` varchar(255) NOT NULL,
  `next_execution_time` int(11) NOT NULL,
  `message` varchar(255) NOT NULL,
  `user_id` int(11) NOT NULL,
  `action` varchar(40) NOT NULL,
  `params` varchar(255) DEFAULT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  `last_run_at` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `servers`
--

DROP TABLE IF EXISTS `servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `url` varchar(255) NOT NULL,
  `authkey` varbinary(255) NOT NULL,
  `org_id` int(11) NOT NULL,
  `push` tinyint(1) NOT NULL,
  `pull` tinyint(1) NOT NULL,
  `push_sightings` tinyint(1) NOT NULL DEFAULT 0,
  `push_galaxy_clusters` tinyint(1) NOT NULL DEFAULT 0,
  `push_analyst_data` tinyint(1) NOT NULL DEFAULT 0,
  `pull_analyst_data` tinyint(1) NOT NULL DEFAULT 0,
  `pull_galaxy_clusters` tinyint(1) NOT NULL DEFAULT 0,
  `lastpulledid` int(11) DEFAULT NULL,
  `lastpushedid` int(11) DEFAULT NULL,
  `organization` varchar(10) DEFAULT NULL,
  `remote_org_id` int(11) NOT NULL,
  `publish_without_email` tinyint(1) NOT NULL DEFAULT 0,
  `unpublish_event` tinyint(1) NOT NULL DEFAULT 0,
  `self_signed` tinyint(1) NOT NULL,
  `pull_rules` text NOT NULL,
  `push_rules` text NOT NULL,
  `cert_file` varchar(255) DEFAULT NULL,
  `client_cert_file` varchar(255) DEFAULT NULL,
  `internal` tinyint(1) NOT NULL DEFAULT 0,
  `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
  `remove_missing_tags` tinyint(1) NOT NULL DEFAULT 0,
  `caching_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `priority` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `priority` (`priority`),
  KEY `remote_org_id` (`remote_org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `shadow_attribute_correlations`
--

DROP TABLE IF EXISTS `shadow_attribute_correlations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shadow_attribute_correlations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `a_distribution` tinyint(4) NOT NULL,
  `sharing_group_id` int(11) DEFAULT NULL,
  `a_sharing_group_id` int(11) DEFAULT NULL,
  `attribute_id` int(11) NOT NULL,
  `1_shadow_attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `1_event_id` int(11) NOT NULL,
  `info` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `attribute_id` (`attribute_id`),
  KEY `a_sharing_group_id` (`a_sharing_group_id`),
  KEY `event_id` (`event_id`),
  KEY `1_event_id` (`1_event_id`),
  KEY `sharing_group_id` (`sharing_group_id`),
  KEY `1_shadow_attribute_id` (`1_shadow_attribute_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `shadow_attributes`
--

DROP TABLE IF EXISTS `shadow_attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `shadow_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `old_id` int(11) DEFAULT 0,
  `event_id` int(11) NOT NULL,
  `type` varchar(100) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `category` varchar(255) NOT NULL,
  `value1` text DEFAULT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `uuid` varchar(40) NOT NULL,
  `value2` text DEFAULT NULL,
  `org_id` int(11) NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  `event_org_id` int(11) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `event_uuid` varchar(40) NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT 0,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `proposal_to_delete` tinyint(1) NOT NULL DEFAULT 0,
  `disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
  `first_seen` bigint(20) DEFAULT NULL,
  `last_seen` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `event_id` (`event_id`),
  KEY `event_uuid` (`event_uuid`),
  KEY `event_org_id` (`event_org_id`),
  KEY `uuid` (`uuid`),
  KEY `old_id` (`old_id`),
  KEY `value1` (`value1`(255)),
  KEY `value2` (`value2`(255)),
  KEY `type` (`type`),
  KEY `category` (`category`),
  KEY `first_seen` (`first_seen`),
  KEY `last_seen` (`last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sharing_group_blueprints`
--

DROP TABLE IF EXISTS `sharing_group_blueprints`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sharing_group_blueprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `sharing_group_id` int(11) DEFAULT NULL,
  `rules` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sharing_group_orgs`
--

DROP TABLE IF EXISTS `sharing_group_orgs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sharing_group_orgs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sharing_group_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `extend` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `org_id` (`org_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sharing_group_servers`
--

DROP TABLE IF EXISTS `sharing_group_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sharing_group_servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sharing_group_id` int(11) NOT NULL,
  `server_id` int(11) NOT NULL,
  `all_orgs` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `server_id` (`server_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sharing_groups`
--

DROP TABLE IF EXISTS `sharing_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sharing_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `releasability` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `uuid` varchar(40) NOT NULL,
  `organisation_uuid` varchar(40) NOT NULL,
  `org_id` int(11) NOT NULL,
  `sync_user_id` int(11) NOT NULL DEFAULT 0,
  `active` tinyint(1) NOT NULL,
  `created` datetime NOT NULL,
  `modified` datetime NOT NULL,
  `local` tinyint(1) NOT NULL,
  `roaming` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  UNIQUE KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `sync_user_id` (`sync_user_id`),
  KEY `organisation_uuid` (`organisation_uuid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sighting_blocklists`
--

DROP TABLE IF EXISTS `sighting_blocklists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sighting_blocklists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `org_uuid` varchar(40) NOT NULL,
  `created` datetime NOT NULL,
  `org_name` varchar(255) NOT NULL,
  `comment` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `org_uuid` (`org_uuid`),
  KEY `org_name` (`org_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sightingdb_orgs`
--

DROP TABLE IF EXISTS `sightingdb_orgs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sightingdb_orgs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sightingdb_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sightingdb_id` (`sightingdb_id`),
  KEY `org_id` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sightingdbs`
--

DROP TABLE IF EXISTS `sightingdbs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sightingdbs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `owner` varchar(255) DEFAULT '',
  `host` varchar(255) DEFAULT 'http://localhost',
  `port` int(11) DEFAULT 9999,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
  `ssl_skip_verification` tinyint(1) NOT NULL DEFAULT 0,
  `namespace` varchar(255) DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  KEY `owner` (`owner`),
  KEY `host` (`host`),
  KEY `port` (`port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sightings`
--

DROP TABLE IF EXISTS `sightings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sightings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attribute_id` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `date_sighting` bigint(20) NOT NULL,
  `uuid` varchar(255) DEFAULT '',
  `source` varchar(255) DEFAULT '',
  `type` int(11) DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `attribute_id` (`attribute_id`),
  KEY `event_id` (`event_id`),
  KEY `org_id` (`org_id`),
  KEY `source` (`source`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `system_settings`
--

DROP TABLE IF EXISTS `system_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_settings` (
  `setting` varchar(255) NOT NULL,
  `value` blob NOT NULL,
  PRIMARY KEY (`setting`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tag_collection_tags`
--

DROP TABLE IF EXISTS `tag_collection_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `tag_collection_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tag_collection_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tag_collection_id` (`tag_collection_id`),
  KEY `tag_id` (`tag_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tag_collections`
--

DROP TABLE IF EXISTS `tag_collections`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `tag_collections` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `org_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `all_orgs` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `user_id` (`user_id`),
  KEY `org_id` (`org_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tags`
--

DROP TABLE IF EXISTS `tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `colour` varchar(7) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `exportable` tinyint(1) NOT NULL,
  `org_id` int(11) NOT NULL DEFAULT 0,
  `user_id` int(11) NOT NULL DEFAULT 0,
  `hide_tag` tinyint(1) NOT NULL DEFAULT 0,
  `numerical_value` int(11) DEFAULT NULL,
  `is_galaxy` tinyint(1) NOT NULL DEFAULT 0,
  `is_custom_galaxy` tinyint(1) NOT NULL DEFAULT 0,
  `local_only` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`),
  KEY `org_id` (`org_id`),
  KEY `user_id` (`user_id`),
  KEY `numerical_value` (`numerical_value`)
) ENGINE=InnoDB AUTO_INCREMENT=13869 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tasks`
--

DROP TABLE IF EXISTS `tasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `tasks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(100) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `timer` int(11) NOT NULL,
  `scheduled_time` varchar(8) NOT NULL DEFAULT '6:00',
  `process_id` varchar(32) DEFAULT NULL,
  `description` varchar(255) NOT NULL,
  `next_execution_time` int(11) NOT NULL,
  `message` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `taxii_servers`
--

DROP TABLE IF EXISTS `taxii_servers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `taxii_servers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `owner` varchar(191) NOT NULL,
  `baseurl` varchar(191) NOT NULL,
  `api_root` varchar(191) NOT NULL DEFAULT '0',
  `description` text DEFAULT NULL,
  `filters` text DEFAULT NULL,
  `api_key` text NOT NULL,
  `collection` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci DEFAULT NULL,
  `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `baseurl` (`baseurl`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `taxonomies`
--

DROP TABLE IF EXISTS `taxonomies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `taxonomies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `namespace` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `version` int(11) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `exclusive` tinyint(1) DEFAULT 0,
  `required` tinyint(1) NOT NULL DEFAULT 0,
  `highlighted` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=166 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `taxonomy_entries`
--

DROP TABLE IF EXISTS `taxonomy_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `taxonomy_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taxonomy_predicate_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `expanded` text DEFAULT NULL,
  `colour` varchar(7) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `numerical_value` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `taxonomy_predicate_id` (`taxonomy_predicate_id`),
  KEY `numerical_value` (`numerical_value`)
) ENGINE=InnoDB AUTO_INCREMENT=11585 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `taxonomy_predicates`
--

DROP TABLE IF EXISTS `taxonomy_predicates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `taxonomy_predicates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `taxonomy_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `expanded` text DEFAULT NULL,
  `colour` varchar(7) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `exclusive` tinyint(1) DEFAULT 0,
  `numerical_value` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `taxonomy_id` (`taxonomy_id`),
  KEY `numerical_value` (`numerical_value`)
) ENGINE=InnoDB AUTO_INCREMENT=1216 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `template_element_attributes`
--

DROP TABLE IF EXISTS `template_element_attributes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `template_element_attributes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `to_ids` tinyint(1) NOT NULL DEFAULT 1,
  `category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `complex` tinyint(1) NOT NULL,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `template_element_files`
--

DROP TABLE IF EXISTS `template_element_files`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `template_element_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_element_id` int(11) NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `category` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `malware` tinyint(1) NOT NULL,
  `mandatory` tinyint(1) NOT NULL,
  `batch` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `template_element_texts`
--

DROP TABLE IF EXISTS `template_element_texts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `template_element_texts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `template_element_id` int(11) NOT NULL,
  `text` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `template_elements`
--

DROP TABLE IF EXISTS `template_elements`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `template_elements` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `position` int(11) NOT NULL,
  `element_definition` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=48 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `template_tags`
--

DROP TABLE IF EXISTS `template_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `template_tags` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `template_id` int(11) NOT NULL,
  `tag_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `templates`
--

DROP TABLE IF EXISTS `templates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `templates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `description` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `org` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `share` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `threads`
--

DROP TABLE IF EXISTS `threads`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `threads` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `distribution` tinyint(4) NOT NULL,
  `user_id` int(11) NOT NULL,
  `post_count` int(11) NOT NULL,
  `event_id` int(11) NOT NULL,
  `title` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `org_id` int(11) NOT NULL,
  `sharing_group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `event_id` (`event_id`),
  KEY `org_id` (`org_id`),
  KEY `sharing_group_id` (`sharing_group_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `threat_levels`
--

DROP TABLE IF EXISTS `threat_levels`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `threat_levels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `form_description` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_login_profiles`
--

DROP TABLE IF EXISTS `user_login_profiles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_login_profiles` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `user_id` int(11) NOT NULL,
  `status` varchar(191) DEFAULT NULL,
  `ip` varchar(191) DEFAULT NULL,
  `user_agent` varchar(191) DEFAULT NULL,
  `accept_lang` varchar(191) DEFAULT NULL,
  `geoip` varchar(191) DEFAULT NULL,
  `ua_platform` varchar(191) DEFAULT NULL,
  `ua_browser` varchar(191) DEFAULT NULL,
  `ua_pattern` varchar(191) DEFAULT NULL,
  `hash` varchar(32) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `hash` (`hash`),
  KEY `ip` (`ip`),
  KEY `status` (`status`),
  KEY `geoip` (`geoip`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_settings`
--

DROP TABLE IF EXISTS `user_settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `value` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `user_id` int(11) NOT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_setting` (`user_id`,`setting`),
  KEY `setting` (`setting`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(255) NOT NULL,
  `org_id` int(11) NOT NULL,
  `server_id` int(11) NOT NULL DEFAULT 0,
  `email` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `autoalert` tinyint(1) NOT NULL DEFAULT 0,
  `authkey` varchar(40) DEFAULT NULL,
  `invited_by` int(11) NOT NULL DEFAULT 0,
  `gpgkey` longtext DEFAULT NULL,
  `certif_public` longtext DEFAULT NULL,
  `nids_sid` int(15) NOT NULL DEFAULT 0,
  `termsaccepted` tinyint(1) NOT NULL DEFAULT 0,
  `newsread` int(11) unsigned DEFAULT 0,
  `role_id` int(11) NOT NULL DEFAULT 0,
  `change_pw` tinyint(1) NOT NULL DEFAULT 0,
  `contactalert` tinyint(1) NOT NULL DEFAULT 0,
  `disabled` tinyint(1) NOT NULL DEFAULT 0,
  `expiration` datetime DEFAULT NULL,
  `current_login` int(11) DEFAULT 0,
  `last_login` int(11) DEFAULT 0,
  `force_logout` tinyint(1) NOT NULL DEFAULT 0,
  `date_created` bigint(20) DEFAULT NULL,
  `date_modified` bigint(20) DEFAULT NULL,
  `sub` varchar(255) DEFAULT NULL,
  `external_auth_required` tinyint(1) NOT NULL DEFAULT 0,
  `external_auth_key` text DEFAULT NULL,
  `last_api_access` int(11) DEFAULT 0,
  `notification_daily` tinyint(1) NOT NULL DEFAULT 0,
  `notification_weekly` tinyint(1) NOT NULL DEFAULT 0,
  `notification_monthly` tinyint(1) NOT NULL DEFAULT 0,
  `totp` varchar(255) DEFAULT NULL,
  `hotp_counter` int(11) DEFAULT NULL,
  `last_pw_change` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `sub` (`sub`),
  KEY `org_id` (`org_id`),
  KEY `server_id` (`server_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_bin;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `warninglist_entries`
--

DROP TABLE IF EXISTS `warninglist_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `warninglist_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `value` text CHARACTER SET utf8mb3 COLLATE utf8mb3_unicode_ci NOT NULL,
  `warninglist_id` int(11) NOT NULL,
  `comment` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `warninglist_id` (`warninglist_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2512730 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `warninglist_types`
--

DROP TABLE IF EXISTS `warninglist_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `warninglist_types` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `warninglist_id` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=571 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `warninglists`
--

DROP TABLE IF EXISTS `warninglists`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `warninglists` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `type` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL DEFAULT 'string',
  `description` text CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `version` int(11) NOT NULL DEFAULT 1,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `default` tinyint(1) NOT NULL DEFAULT 1,
  `category` varchar(20) NOT NULL DEFAULT 'false_positive',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=123 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `workflow_blueprints`
--

DROP TABLE IF EXISTS `workflow_blueprints`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `workflow_blueprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `description` varchar(191) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `default` tinyint(1) NOT NULL DEFAULT 0,
  `data` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `workflows`
--

DROP TABLE IF EXISTS `workflows`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `workflows` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(40) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `name` varchar(191) NOT NULL,
  `description` varchar(191) NOT NULL,
  `timestamp` int(11) NOT NULL DEFAULT 0,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `counter` int(11) NOT NULL DEFAULT 0,
  `trigger_id` varchar(191) CHARACTER SET utf8mb3 COLLATE utf8mb3_bin NOT NULL,
  `debug_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `data` longtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `uuid` (`uuid`),
  KEY `name` (`name`),
  KEY `timestamp` (`timestamp`),
  KEY `trigger_id` (`trigger_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-08-05 18:55:38
