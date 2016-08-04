/*
 * db.cpp
 *
 *  Created on: Aug 2, 2016
 *      Author: nsamson
 */

#include <leveldb/db.h>
#include <map>
#include <cstring>
#include "udg_sec_u.h"

struct DBStore {
	int created_sessions = 0;

	std::map<int, leveldb::DB*> open_dbs;

	~DBStore() {
		for (auto& pair : open_dbs) {
			delete pair.second;
		}
	}

	int add_db(leveldb::DB* to_store) {
		open_dbs[created_sessions] = to_store;
		int ret = created_sessions;
		created_sessions++;
		return ret;
	}

	void close_db(int db_ref) {
		delete open_dbs[db_ref];
		open_dbs.erase(db_ref);
	}
};

DBStore dbs;

void ocall_db_open(int* ret, const char* db_name, int create_if_not_exsts) {

	leveldb::Options opts;
	opts.create_if_missing = create_if_not_exsts != 0 ? true : false;
	leveldb::DB* db;
	leveldb::Status status = leveldb::DB::Open(opts, db_name, &db);

	if (!status.ok()) {
		*ret = -1;
	} else {
		*ret = dbs.add_db(db);
	}

}

void ocall_db_close(int to_close) {
	dbs.close_db(to_close);
}

void ocall_db_put(int db_ref, const char* key, const char* value) {
	leveldb::DB* db;
	db = dbs.open_dbs[db_ref];

	leveldb::WriteOptions wr_opts;
	wr_opts.sync = true;

	db->Put(wr_opts, key, value);
}

void ocall_db_get(long* ret_bytes, int db_ref, const char* key, char* value, size_t buf_len) {
	leveldb::DB* db;
	db = dbs.open_dbs[db_ref];

	leveldb::ReadOptions rd_opt;

	std::string val;
	leveldb::Status status = db->Get(rd_opt, key, &val);

	if (!status.ok()) {
		*ret_bytes = -1;
	} else {
		long len = buf_len > val.length() ? val.length() : buf_len;
		memcpy(value, val.c_str(), len);
		*ret_bytes = len;
	}

}

void ocall_db_del(int db_ref, const char* key) {
	leveldb::DB* db;
	db = dbs.open_dbs[db_ref];

	leveldb::WriteOptions wr_opts;
	wr_opts.sync = true;

	db->Delete(wr_opts, key);
}


