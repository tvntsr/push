# create tables
DROP TABLE IF EXISTS push_apns;
CREATE TABLE push_apns (
  id int(11) unsigned NOT NULL AUTO_INCREMENT,
  aor varchar(512) NOT NULL,
  device_id varchar(64) NOT NULL,
  callid varchar(255) NOT NULL, 
  registered TIMESTAMP NOT NULL default CURRENT_TIMESTAMP,
  PRIMARY KEY  (id),
  UNIQUE INDEX aor(aor(512))
);

delete from version where table_name="push_apns";
insert into version values("push_apns", 1);

