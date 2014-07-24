# create tables
DROP TABLE IF EXISTS push_apns;
CREATE TABLE push_apns (
  id int(11) unsigned NOT NULL AUTO_INCREMENT,
  aor varchar(512) NOT NULL,
  device_id varchar(32) NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE INDEX aor(aor(512))
);

delete from version where table_name="push";
insert into version values("push", 1);

