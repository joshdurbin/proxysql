#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include <string>       // std::string
#include <sstream>      // std::ostringstream  
#include <iomanip>      // std::setprecision
#include "proxysql.h"
#include "cpp.h"

#include "Command_Counter.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Query_Processor.h"

extern MySQL_Threads_Handler *GloMTH;
extern ProxySQL_Admin *GloAdmin;

static __thread Command_Counter* _thr_commands_counters[MYSQL_COM_QUERY___NONE];

static char* commands_counters_desc[MYSQL_COM_QUERY___NONE] = {
	[MYSQL_COM_QUERY_ALTER_TABLE] = (char*)"ALTER_TABLE",
	[MYSQL_COM_QUERY_ALTER_VIEW] = (char*)"ALTER_VIEW",
	[MYSQL_COM_QUERY_ANALYZE_TABLE] = (char*)"ANALYZE_TABLE",
	[MYSQL_COM_QUERY_BEGIN] = (char*)"BEGIN",
	[MYSQL_COM_QUERY_CALL] = (char*)"CALL",
	[MYSQL_COM_QUERY_CHANGE_MASTER] = (char*)"CHANGE_MASTER",
	[MYSQL_COM_QUERY_CHANGE_REPLICATION_SOURCE] = (char*)"MYSQL_COM_QUERY_CHANGE_REPLICATION_SOURCE",
	[MYSQL_COM_QUERY_COMMIT] = (char*)"COMMIT",
	[MYSQL_COM_QUERY_CREATE_DATABASE] = (char*)"CREATE_DATABASE",
	[MYSQL_COM_QUERY_CREATE_INDEX] = (char*)"CREATE_INDEX",
	[MYSQL_COM_QUERY_CREATE_TABLE] = (char*)"CREATE_TABLE",
	[MYSQL_COM_QUERY_CREATE_TEMPORARY] = (char*)"CREATE_TEMPORARY",
	[MYSQL_COM_QUERY_CREATE_TRIGGER] = (char*)"CREATE_TRIGGER",
	[MYSQL_COM_QUERY_CREATE_USER] = (char*)"CREATE_USER",
	[MYSQL_COM_QUERY_CREATE_VIEW] = (char*)"CREATE_VIEW",
	[MYSQL_COM_QUERY_DEALLOCATE] = (char*)"DEALLOCATE",
	[MYSQL_COM_QUERY_DELETE] = (char*)"DELETE",
	[MYSQL_COM_QUERY_DESCRIBE] = (char*)"DESCRIBE",
	[MYSQL_COM_QUERY_DROP_DATABASE] = (char*)"DROP_DATABASE",
	[MYSQL_COM_QUERY_DROP_INDEX] = (char*)"DROP_INDEX",
	[MYSQL_COM_QUERY_DROP_TABLE] = (char*)"DROP_TABLE",
	[MYSQL_COM_QUERY_DROP_TRIGGER] = (char*)"DROP_TRIGGER",
	[MYSQL_COM_QUERY_DROP_USER] = (char*)"DROP_USER",
	[MYSQL_COM_QUERY_DROP_VIEW] = (char*)"DROP_VIEW",
	[MYSQL_COM_QUERY_GRANT] = (char*)"GRANT",
	[MYSQL_COM_QUERY_EXECUTE] = (char*)"EXECUTE",
	[MYSQL_COM_QUERY_EXPLAIN] = (char*)"EXPLAIN",
	[MYSQL_COM_QUERY_FLUSH] = (char*)"FLUSH",
	[MYSQL_COM_QUERY_INSERT] = (char*)"INSERT",
	[MYSQL_COM_QUERY_KILL] = (char*)"KILL",
	[MYSQL_COM_QUERY_LOAD] = (char*)"LOAD",
	[MYSQL_COM_QUERY_LOCK_TABLE] = (char*)"LOCK_TABLE",
	[MYSQL_COM_QUERY_OPTIMIZE] = (char*)"OPTIMIZE",
	[MYSQL_COM_QUERY_PREPARE] = (char*)"PREPARE",
	[MYSQL_COM_QUERY_PURGE] = (char*)"PURGE",
	[MYSQL_COM_QUERY_RELEASE_SAVEPOINT] = (char*)"RELEASE_SAVEPOINT",
	[MYSQL_COM_QUERY_RENAME_TABLE] = (char*)"RENAME_TABLE",
	[MYSQL_COM_QUERY_RESET_MASTER] = (char*)"RESET_MASTER",
	[MYSQL_COM_QUERY_RESET_BINARY_LOGS_AND_GTIDS] = (char*)"RESET_BINARY_LOGS_AND_GTIDS",
	[MYSQL_COM_QUERY_RESET_SLAVE] = (char*)"RESET_SLAVE",
	[MYSQL_COM_QUERY_RESET_REPLICA] = (char*)"RESET_REPLICA",
	[MYSQL_COM_QUERY_REPLACE] = (char*)"REPLACE",
	[MYSQL_COM_QUERY_REVOKE] = (char*)"REVOKE",
	[MYSQL_COM_QUERY_ROLLBACK] = (char*)"ROLLBACK",
	[MYSQL_COM_QUERY_ROLLBACK_SAVEPOINT] = (char*)"ROLLBACK_SAVEPOINT",
	[MYSQL_COM_QUERY_SAVEPOINT] = (char*)"SAVEPOINT",
	[MYSQL_COM_QUERY_SELECT] = (char*)"SELECT",
	[MYSQL_COM_QUERY_SELECT_FOR_UPDATE] = (char*)"SELECT_FOR_UPDATE",
	[MYSQL_COM_QUERY_SET] = (char*)"SET",
	[MYSQL_COM_QUERY_SHOW_TABLE_STATUS] = (char*)"SHOW_TABLE_STATUS",
	[MYSQL_COM_QUERY_START_TRANSACTION] = (char*)"START_TRANSACTION",
	[MYSQL_COM_QUERY_TRUNCATE_TABLE] = (char*)"TRUNCATE_TABLE",
	[MYSQL_COM_QUERY_UNLOCK_TABLES] = (char*)"UNLOCK_TABLES",
	[MYSQL_COM_QUERY_UPDATE] = (char*)"UPDATE",
	[MYSQL_COM_QUERY_USE] = (char*)"USE",
	[MYSQL_COM_QUERY_SHOW] = (char*)"SHOW",
	[MYSQL_COM_QUERY_UNKNOWN] = (char*)"UNKNOWN"
};

MySQL_Rule_Text::MySQL_Rule_Text(const MySQL_Query_Processor_Rule_t* mqr) {
	num_fields = 36; // this count the number of fields
	pta = NULL;
	pta = (char**)malloc(sizeof(char*) * num_fields);
	itostr(pta[0], (long long)mqr->rule_id);
	itostr(pta[1], (long long)mqr->active);
	pta[2] = strdup_null(mqr->username);
	pta[3] = strdup_null(mqr->schemaname);
	itostr(pta[4], (long long)mqr->flagIN);

	pta[5] = strdup_null(mqr->client_addr);
	pta[6] = strdup_null(mqr->proxy_addr);
	itostr(pta[7], (long long)mqr->proxy_port);

	char buf[20];
	if (mqr->digest) {
		sprintf(buf, "0x%016llX", (long long unsigned int)mqr->digest);
		pta[8] = strdup(buf);
	}
	else {
		pta[8] = NULL;
	}

	pta[9] = strdup_null(mqr->match_digest);
	pta[10] = strdup_null(mqr->match_pattern);
	itostr(pta[11], (long long)mqr->negate_match_pattern);
	std::string re_mod;
	re_mod = "";
	if ((mqr->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) re_mod = "CASELESS";
	if ((mqr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
		if (re_mod.length()) {
			re_mod = re_mod + ",";
		}
		re_mod = re_mod + "GLOBAL";
	}
	pta[12] = strdup_null((char*)re_mod.c_str()); // re_modifiers
	itostr(pta[13], (long long)mqr->flagOUT);
	pta[14] = strdup_null(mqr->replace_pattern);
	itostr(pta[15], (long long)mqr->destination_hostgroup);
	itostr(pta[16], (long long)mqr->cache_ttl);
	itostr(pta[17], (long long)mqr->cache_empty_result);
	itostr(pta[18], (long long)mqr->cache_timeout);
	itostr(pta[19], (long long)mqr->reconnect);
	itostr(pta[20], (long long)mqr->timeout);
	itostr(pta[21], (long long)mqr->retries);
	itostr(pta[22], (long long)mqr->delay);
	itostr(pta[23], (long long)mqr->next_query_flagIN);
	itostr(pta[24], (long long)mqr->mirror_flagOUT);
	itostr(pta[25], (long long)mqr->mirror_hostgroup);
	pta[26] = strdup_null(mqr->error_msg);
	pta[27] = strdup_null(mqr->OK_msg);
	itostr(pta[28], (long long)mqr->sticky_conn);
	itostr(pta[29], (long long)mqr->multiplex);
	itostr(pta[30], (long long)mqr->gtid_from_hostgroup);
	itostr(pta[31], (long long)mqr->log);
	itostr(pta[32], (long long)mqr->apply);
	pta[33] = strdup_null(mqr->attributes);
	pta[34] = strdup_null(mqr->comment); // issue #643
	itostr(pta[35], (long long)mqr->hits);
}

MySQL_Query_Processor::MySQL_Query_Processor() : 
	Query_Processor<MySQL_Query_Processor>(GloMTH->get_variable_int("query_rules_fast_routing_algorithm")) {
	
	for (int i = 0; i < MYSQL_COM_QUERY___NONE; i++) commands_counters[i] = new Command_Counter(i,15,commands_counters_desc);
	
	latency_tracker = new CommandLatencyTracker(MYSQL_COM_QUERY___NONE);
	
	// DISABLED: Don't call update_tdigest_configuration() in constructor
	// Thread-local variables may not be initialized yet!
	// Configuration will be updated on first metrics call
	// update_tdigest_configuration();
	
	// Initialize Prometheus latency quantile family (will be initialized on first use if null)
	p_latency_quantile_family = nullptr;

	//if (GloMTH) {
	//	query_rules_fast_routing_algorithm = GloMTH->get_variable_int("query_rules_fast_routing_algorithm");
	//}
}

MySQL_Query_Processor::~MySQL_Query_Processor() {
	for (int i = 0; i < MYSQL_COM_QUERY___NONE; i++) delete commands_counters[i];
	if (latency_tracker) {
		delete latency_tracker;
		latency_tracker = nullptr;
	}
}

enum MYSQL_COM_QUERY_command MySQL_Query_Processor::query_parser_command_type(SQP_par_t* qp) {
	char* text = NULL; // this new variable is a pointer to either qp->digest_text , or to the query
	if (qp->digest_text) {
		text = qp->digest_text;
	} else {
		text = qp->query_prefix;
	}

	enum MYSQL_COM_QUERY_command ret = MYSQL_COM_QUERY_UNKNOWN;
	char c1;

	tokenizer_t tok;
	tokenizer(&tok, text, " ", TOKENIZER_NO_EMPTIES);
	char* token = NULL;
__get_token:
	token = (char*)tokenize(&tok);
	if (token == NULL) {
		goto __exit__query_parser_command_type;
	}
__remove_paranthesis:
	if (token[0] == '(') {
		if (strlen(token) > 1) {
			token++;
			goto __remove_paranthesis;
		}
		else {
			goto __get_token;
		}
	}
	c1 = token[0];
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Command:%s Prefix:%c\n", token, c1);
	switch (c1) {
	case 'a':
	case 'A':
		if (!mystrcasecmp("ALTER", token)) { // ALTER [ONLINE | OFFLINE] [IGNORE] TABLE
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!mystrcasecmp("TABLE", token)) {
				ret = MYSQL_COM_QUERY_ALTER_TABLE;
				break;
			}
			else {
				if (!mystrcasecmp("OFFLINE", token) || !mystrcasecmp("ONLINE", token)) {
					token = (char*)tokenize(&tok);
					if (token == NULL) break;
					if (!mystrcasecmp("TABLE", token)) {
						ret = MYSQL_COM_QUERY_ALTER_TABLE;
						break;
					}
					else {
						if (!mystrcasecmp("IGNORE", token)) {
							if (token == NULL) break;
							token = (char*)tokenize(&tok);
							if (!mystrcasecmp("TABLE", token)) {
								ret = MYSQL_COM_QUERY_ALTER_TABLE;
								break;
							}
						}
					}
				}
				else {
					if (!mystrcasecmp("IGNORE", token)) {
						if (token == NULL) break;
						token = (char*)tokenize(&tok);
						if (!mystrcasecmp("TABLE", token)) {
							ret = MYSQL_COM_QUERY_ALTER_TABLE;
							break;
						}
					}
				}
			}
			if (!mystrcasecmp("VIEW", token)) {
				ret = MYSQL_COM_QUERY_ALTER_VIEW;
				break;
			}
			break;
		}
		if (!mystrcasecmp("ANALYZE", token)) { // ANALYZE [NO_WRITE_TO_BINLOG | LOCAL] TABLE
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) {
				ret = MYSQL_COM_QUERY_ANALYZE_TABLE;
			}
			else {
				if (!strcasecmp("NO_WRITE_TO_BINLOG", token) || !strcasecmp("LOCAL", token)) {
					token = (char*)tokenize(&tok);
					if (token == NULL) break;
					if (!strcasecmp("TABLE", token)) {
						ret = MYSQL_COM_QUERY_ANALYZE_TABLE;
					}
				}
			}
			break;
		}
		break;
	case 'b':
	case 'B':
		if (!strcasecmp("BEGIN", token)) { // BEGIN
			ret = MYSQL_COM_QUERY_BEGIN;
		}
		break;
	case 'c':
	case 'C':
		if (!strcasecmp("CALL", token)) { // CALL
			ret = MYSQL_COM_QUERY_CALL;
			break;
		}
		if (!strcasecmp("CHANGE", token)) { // CHANGE
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("MASTER", token)) {
				ret = MYSQL_COM_QUERY_CHANGE_MASTER;
				break;
			}
			if (!strcasecmp("REPLICATION", token)) {
				ret = MYSQL_COM_QUERY_CHANGE_REPLICATION_SOURCE;
				break;
			}
			break;
		}
		if (!strcasecmp("COMMIT", token)) { // COMMIT
			ret = MYSQL_COM_QUERY_COMMIT;
			break;
		}
		if (!strcasecmp("CREATE", token)) { // CREATE
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("DATABASE", token)) {
				ret = MYSQL_COM_QUERY_CREATE_DATABASE;
				break;
			}
			if (!strcasecmp("INDEX", token)) {
				ret = MYSQL_COM_QUERY_CREATE_INDEX;
				break;
			}
			if (!strcasecmp("SCHEMA", token)) {
				ret = MYSQL_COM_QUERY_CREATE_DATABASE;
				break;
			}
			if (!strcasecmp("TABLE", token)) {
				ret = MYSQL_COM_QUERY_CREATE_TABLE;
				break;
			}
			if (!strcasecmp("TEMPORARY", token)) {
				ret = MYSQL_COM_QUERY_CREATE_TEMPORARY;
				break;
			}
			if (!strcasecmp("TRIGGER", token)) {
				ret = MYSQL_COM_QUERY_CREATE_TRIGGER;
				break;
			}
			if (!strcasecmp("USER", token)) {
				ret = MYSQL_COM_QUERY_CREATE_USER;
				break;
			}
			if (!strcasecmp("VIEW", token)) {
				ret = MYSQL_COM_QUERY_CREATE_VIEW;
				break;
			}
			break;
		}
		break;
	case 'd':
	case 'D':
		if (!strcasecmp("DEALLOCATE", token)) { // DEALLOCATE PREPARE
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("PREPARE", token)) {
				ret = MYSQL_COM_QUERY_DEALLOCATE;
				break;
			}
		}
		if (!strcasecmp("DELETE", token)) { // DELETE
			ret = MYSQL_COM_QUERY_DELETE;
			break;
		}
		if (!strcasecmp("DESCRIBE", token)) { // DESCRIBE
			ret = MYSQL_COM_QUERY_DESCRIBE;
			break;
		}
		if (!strcasecmp("DROP", token)) { // DROP
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) {
				ret = MYSQL_COM_QUERY_DROP_TABLE;
				break;
			}
			if (!strcasecmp("TRIGGER", token)) {
				ret = MYSQL_COM_QUERY_DROP_TRIGGER;
				break;
			}
			if (!strcasecmp("USER", token)) {
				ret = MYSQL_COM_QUERY_DROP_USER;
				break;
			}
			if (!strcasecmp("VIEW", token)) {
				ret = MYSQL_COM_QUERY_DROP_VIEW;
				break;
			}
		}
		break;
	case 'e':
	case 'E':
		if (!strcasecmp("EXECUTE", token)) { // EXECUTE
			ret = MYSQL_COM_QUERY_EXECUTE;
		}
		break;
	case 'f':
	case 'F':
		if (!strcasecmp("FLUSH", token)) { // FLUSH
			ret = MYSQL_COM_QUERY_FLUSH;
			break;
		}
		break;
	case 'g':
	case 'G':
		if (!strcasecmp("GRANT", token)) { // GRANT
			ret = MYSQL_COM_QUERY_GRANT;
			break;
		}
		break;
	case 'i':
	case 'I':
		if (!strcasecmp("INSERT", token)) { // INSERT
			ret = MYSQL_COM_QUERY_INSERT;
			break;
		}
		break;
	case 'k':
	case 'K':
		if (!strcasecmp("KILL", token)) { // KILL
			ret = MYSQL_COM_QUERY_KILL;
			break;
		}
		break;
	case 'l':
	case 'L':
		if (!strcasecmp("LOCK", token)) { // LOCK
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) {
				ret = MYSQL_COM_QUERY_LOCK_TABLE;
				break;
			}
		}
		if (!strcasecmp("LOAD", token)) { // LOAD
			ret = MYSQL_COM_QUERY_LOAD;
			break;
		}
		break;
	case 'o':
	case 'O':
		if (!strcasecmp("OPTIMIZE", token)) { // OPTIMIZE
			ret = MYSQL_COM_QUERY_OPTIMIZE;
			break;
		}
		break;
	case 'p':
	case 'P':
		if (!strcasecmp("PREPARE", token)) { // PREPARE
			ret = MYSQL_COM_QUERY_PREPARE;
			break;
		}
		if (!strcasecmp("PURGE", token)) { // PURGE
			ret = MYSQL_COM_QUERY_PURGE;
			break;
		}
		break;
	case 'r':
	case 'R':
		if (!strcasecmp("RELEASE", token)) { // RELEASE
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("SAVEPOINT", token)) {
				ret = MYSQL_COM_QUERY_RELEASE_SAVEPOINT;
				break;
			}
		}
		if (!strcasecmp("RENAME", token)) { // RENAME
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) {
				ret = MYSQL_COM_QUERY_RENAME_TABLE;
				break;
			}
		}
		if (!strcasecmp("REPLACE", token)) { // REPLACE
			ret = MYSQL_COM_QUERY_REPLACE;
			break;
		}
		if (!strcasecmp("RESET", token)) { // RESET
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("MASTER", token)) {
				ret = MYSQL_COM_QUERY_RESET_MASTER;
				break;
			}
			if (!strcasecmp("BINARY", token)) {
				ret = MYSQL_COM_QUERY_RESET_BINARY_LOGS_AND_GTIDS;
				break;
			}
			if (!strcasecmp("SLAVE", token)) {
				ret = MYSQL_COM_QUERY_RESET_SLAVE;
				break;
			}
			if (!strcasecmp("REPLICA", token)) {
				ret = MYSQL_COM_QUERY_RESET_REPLICA;
				break;
			}
			break;
		}
		if (!strcasecmp("REVOKE", token)) { // REVOKE
			ret = MYSQL_COM_QUERY_REVOKE;
			break;
		}
		if (!strcasecmp("ROLLBACK", token)) { // ROLLBACK
			token = (char*)tokenize(&tok);
			if (token == NULL) {
				ret = MYSQL_COM_QUERY_ROLLBACK;
				break;
			}
			else {
				if (!strcasecmp("TO", token)) {
					token = (char*)tokenize(&tok);
					if (token == NULL) break;
					if (!strcasecmp("SAVEPOINT", token)) {
						ret = MYSQL_COM_QUERY_ROLLBACK_SAVEPOINT;
						break;
					}
				}
			}
			break;
		}
		break;
	case 's':
	case 'S':
		if (!mystrcasecmp("SAVEPOINT", token)) { // SAVEPOINT
			ret = MYSQL_COM_QUERY_SAVEPOINT;
			break;
		}
		if (!mystrcasecmp("SELECT", token)) { // SELECT
			ret = MYSQL_COM_QUERY_SELECT;
			break;
			// FIXME: SELECT FOR UPDATE is not implemented
		}
		if (!mystrcasecmp("SET", token)) { // SET
			ret = MYSQL_COM_QUERY_SET;
			break;
		}
		if (!mystrcasecmp("SHOW", token)) { // SHOW
			ret = MYSQL_COM_QUERY_SHOW;
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) {
				token = (char*)tokenize(&tok);
				if (token == NULL) break;
				if (!strcasecmp("STATUS", token)) {
					ret = MYSQL_COM_QUERY_SHOW_TABLE_STATUS;
				}
			}
			break;
		}
		if (!mystrcasecmp("START", token)) { // START
			token = (char*)tokenize(&tok);
			if (token == NULL) break;
			if (!strcasecmp("TRANSACTION", token)) {
				ret = MYSQL_COM_QUERY_START_TRANSACTION;
			}
			break;
		}
		break;
	case 't':
	case 'T':
		if (!strcasecmp("TRUNCATE", token)) { // TRUNCATE
			if (token == NULL) break;
			if (!strcasecmp("TABLE", token)) {
				ret = MYSQL_COM_QUERY_TRUNCATE_TABLE;
				break;
			}
		}
		break;
	case 'u':
	case 'U':
		if (!strcasecmp("UNLOCK", token)) { // UNLOCK
			ret = MYSQL_COM_QUERY_UNLOCK_TABLES;
			break;
		}
		if (!strcasecmp("UPDATE", token)) { // UPDATE
			ret = MYSQL_COM_QUERY_UPDATE;
			break;
		}
		break;
	default:
		break;
	}

__exit__query_parser_command_type:
	free_tokenizer(&tok);
	if (qp->query_prefix) {
		free(qp->query_prefix);
		qp->query_prefix = NULL;
	}
	return ret;
}

bool MySQL_Query_Processor::_is_valid_gtid(char* gtid, size_t gtid_len) {
	if (gtid_len < 3) {
		return false;
	}
	char* sep_pos = index(gtid, ':');
	if (sep_pos == NULL) {
		return false;
	}
	size_t uuid_len = sep_pos - gtid;
	if (uuid_len < 1) {
		return false;
	}
	if (gtid_len < uuid_len + 2) {
		return false;
	}
	return true;
}

void MySQL_Query_Processor::update_query_processor_stats() {
	Query_Processor::update_query_processor_stats();

	for (int i = 0; i < MYSQL_COM_QUERY___NONE; i++) {
		commands_counters[i]->add_and_reset(_thr_commands_counters[i]);
	}
}

void MySQL_Query_Processor::init_thread() {
	Query_Processor::init_thread();
	for (int i = 0; i < MYSQL_COM_QUERY___NONE; i++) _thr_commands_counters[i] = new Command_Counter(i,15,commands_counters_desc);
}

void MySQL_Query_Processor::end_thread() {
	Query_Processor::end_thread();
	for (int i = 0; i < MYSQL_COM_QUERY___NONE; i++) delete _thr_commands_counters[i];
};

unsigned long long MySQL_Query_Processor::query_parser_update_counters(MySQL_Session* sess, enum MYSQL_COM_QUERY_command c, SQP_par_t* qp, unsigned long long t) {
	if (c >= MYSQL_COM_QUERY___NONE) return 0;
	unsigned long long ret = _thr_commands_counters[c]->add_time(t);
	
	// Record latency in t-digest for quantile computation
	latency_tracker->record_latency(static_cast<size_t>(c), t);
	
	uint64_t digest = 0;
	char* digest_text = NULL;
	if (sess->CurrentQuery.stmt_info == NULL && qp->digest_text) {
		digest = qp->digest;
		digest_text = qp->digest_text;
	} else if (sess->CurrentQuery.stmt_info && sess->CurrentQuery.stmt_info->digest_text) {
		MySQL_STMT_Global_info* stmt_info = sess->CurrentQuery.stmt_info;
		digest = stmt_info->digest;
		digest_text = stmt_info->digest_text;
	}
	if (digest_text)
		Query_Processor::query_parser_update_counters(sess, qp->digest_total, digest, digest_text, t);
	return ret;
}

SQLite3_result* MySQL_Query_Processor::get_stats_commands_counters() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping commands counters\n");
	SQLite3_result* result = new SQLite3_result(15);
	result->add_column_definition(SQLITE_TEXT, "Command");
	result->add_column_definition(SQLITE_TEXT, "Total_Cnt");
	result->add_column_definition(SQLITE_TEXT, "Total_Time_us");
	result->add_column_definition(SQLITE_TEXT, "cnt_100us");
	result->add_column_definition(SQLITE_TEXT, "cnt_500us");
	result->add_column_definition(SQLITE_TEXT, "cnt_1ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_5ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_10ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_50ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_100ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_500ms");
	result->add_column_definition(SQLITE_TEXT, "cnt_1s");
	result->add_column_definition(SQLITE_TEXT, "cnt_5s");
	result->add_column_definition(SQLITE_TEXT, "cnt_10s");
	result->add_column_definition(SQLITE_TEXT, "cnt_INFs");
	for (int i = 0; i < MYSQL_COM_QUERY__UNINITIALIZED; i++) {
		char** pta = commands_counters[i]->get_row();
		result->add_row(pta);
		commands_counters[i]->free_row(pta);
	}
	return result;
}

SQLite3_result* MySQL_Query_Processor::get_stats_latency_quantiles() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping latency quantiles\n");
	
	// Get configured quantiles dynamically
	std::vector<double> quantiles = latency_tracker->get_configured_quantiles();
	
	// Create result with dynamic column count (2 fixed columns + quantile columns)
	int total_columns = 2 + quantiles.size();
	SQLite3_result* result = new SQLite3_result(total_columns);
	
	// Add fixed columns
	result->add_column_definition(SQLITE_TEXT, "Command");
	result->add_column_definition(SQLITE_TEXT, "Query_Count");
	
	// Add dynamic quantile columns
	for (size_t i = 0; i < quantiles.size(); i++) {
		std::ostringstream col_name;
		col_name << "p" << std::fixed << std::setprecision(0) << (quantiles[i] * 100) << "_us";
		result->add_column_definition(SQLITE_TEXT, col_name.str().c_str());
	}
	
	for (int i = 0; i < MYSQL_COM_QUERY___NONE; i++) {
		if (latency_tracker->get_query_count(i) > 0) {
			char** pta = (char**)malloc(sizeof(char*) * total_columns);
			
			// Command name
			pta[0] = commands_counters_desc[i];
			
			// Query count
			char* query_count = (char*)malloc(32);
			sprintf(query_count, "%llu", (unsigned long long)latency_tracker->get_query_count(i));
			pta[1] = query_count;
			
			// Get quantile values
			std::vector<double> q_values = latency_tracker->get_quantiles(i, quantiles);
			
			// Fill dynamic quantile columns
			for (size_t j = 0; j < quantiles.size(); j++) {
				char* quantile_val = (char*)malloc(32);
				if (j < q_values.size() && !std::isnan(q_values[j])) {
					sprintf(quantile_val, "%.0f", q_values[j]);
				} else {
					sprintf(quantile_val, "0");
				}
				pta[2 + j] = quantile_val;
			}
			
			result->add_row(pta);
			
			// Free allocated memory (except command name which is static)
			for (int j = 1; j < total_columns; j++) {
				free(pta[j]);
			}
			free(pta);
		}
	}
	
	return result;
}

void MySQL_Query_Processor::p_update_latency_metrics() {
	// Ensure we have the latest configuration
	update_tdigest_configuration();
	
	// Update prometheus latency quantile metrics for all command types
	if (!latency_tracker || !latency_tracker->is_enabled()) {
		return; // Skip if t-digest is disabled
	}
	
	// Initialize Prometheus family if needed and registry is available
	if (p_latency_quantile_family == nullptr) {
		if (GloVars.prometheus_registry != nullptr) {
			try {
				p_latency_quantile_family = &prometheus::BuildGauge()
					.Name("proxysql_query_latency_quantile_seconds")
					.Help("Query latency quantiles by command type")
					.Register(*GloVars.prometheus_registry);
			} catch (const std::exception& e) {
				// Failed to initialize prometheus family, skip metrics update
				proxy_error("MySQL t-digest: Failed to register Prometheus family: %s\n", e.what());
				return;
			}
		} else {
			// Prometheus registry not available yet
			return;
		}
	}
	
	std::vector<double> quantiles = latency_tracker->get_configured_quantiles();
	if (quantiles.empty()) {
		quantiles = {0.5, 0.9, 0.95, 0.99}; // Fallback defaults
	}
	
	for (int i = 0; i < MYSQL_COM_QUERY___NONE; i++) {
		uint64_t query_count = latency_tracker->get_query_count(i);
		if (query_count > 0) {
			std::vector<double> q_values = latency_tracker->get_quantiles(i, quantiles);
			const char* command_name = commands_counters_desc[i];
			
			// Safety check for command name
			if (!command_name) {
				continue;
			}
			
			for (size_t j = 0; j < quantiles.size() && j < q_values.size(); j++) {
				
				// Accept any finite value, including zero and negative (which we'll clamp)
				if (std::isfinite(q_values[j])) {
					try {
						// Create quantile label string
						std::ostringstream quantile_label_stream;
						quantile_label_stream << std::fixed << std::setprecision(3) << quantiles[j];
						std::string quantile_label = quantile_label_stream.str();
						
						std::string metric_id = std::string(command_name) + "_" + quantile_label;
						
						std::map<std::string, std::string> labels = {
							{"command", command_name},
							{"quantile", quantile_label}
						};
						
						// Find or create the gauge
						auto it = p_latency_quantile_map.find(metric_id);
						if (it == p_latency_quantile_map.end()) {
							prometheus::Gauge* gauge = &(p_latency_quantile_family->Add(labels));
							p_latency_quantile_map[metric_id] = gauge;
							it = p_latency_quantile_map.find(metric_id);
						}
						
						// Convert microseconds to seconds for Prometheus, ensuring non-negative
						double latency_seconds = std::max(0.0, q_values[j] / 1000000.0);
						it->second->Set(latency_seconds);
					} catch (const std::exception& e) {
						// Skip this metric if there's an error
						proxy_error("MySQL t-digest: Exception when setting gauge: %s\n", e.what());
						continue;
					}
				}
			}
		}
	}
}

MySQL_Query_Processor_Output* MySQL_Query_Processor::process_query(MySQL_Session* sess, void* ptr, unsigned int size, Query_Info* qi) {
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	// to avoid unnecssary deallocation/allocation, we initialize qpo witout new allocation
	MySQL_Query_Processor_Output* ret = sess->qpo;
	ret->init();

	SQP_par_t stmt_exec_qp;
	SQP_par_t* qp = NULL;
	if (qi) {
		// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
		if (ptr) {
			qp = (SQP_par_t*)&qi->QueryParserArgs;
		}
		else {
			qp = &stmt_exec_qp;
			qp->digest = qi->stmt_info->digest;
			qp->digest_text = qi->stmt_info->digest_text;
			qp->first_comment = qi->stmt_info->first_comment;
		}
	}
#define stackbuffer_size 128
	char stackbuffer[stackbuffer_size];
	unsigned int len = 0;
	char* query = NULL;
	// NOTE: if ptr == NULL , we are calling process_mysql_query() on an STMT_EXECUTE
	if (ptr) {
		len = size - sizeof(mysql_hdr) - 1;
		if (len < stackbuffer_size) {
			query = stackbuffer;
		}
		else {
			query = (char*)l_alloc(len + 1);
		}
		memcpy(query, (char*)ptr + sizeof(mysql_hdr) + 1, len);
		query[len] = 0;
	}
	else {
		query = qi->stmt_info->query;
		len = qi->stmt_info->query_length;
	}

	Query_Processor::process_query(sess, ptr == NULL, query, len, ret, qp);

	// FIXME : there is too much data being copied around
	if (len < stackbuffer_size) {
		// query is in the stack
	} else {
		if (ptr) {
			l_free(len + 1, query);
		}
	}

	return ret;
}

MySQL_Query_Processor_Rule_t* MySQL_Query_Processor::new_query_rule(int rule_id, bool active, const char* username, const char* schemaname, int flagIN, const char* client_addr,
	const char* proxy_addr, int proxy_port, const char* digest, const char* match_digest, const char* match_pattern, bool negate_match_pattern,
	const char* re_modifiers, int flagOUT, const char* replace_pattern, int destination_hostgroup, int cache_ttl, int cache_empty_result,
	int cache_timeout, int reconnect, int timeout, int retries, int delay, int next_query_flagIN, int mirror_flagOUT, 
	int mirror_hostgroup, const char* error_msg, const char* OK_msg, int sticky_conn, int multiplex, int gtid_from_hostgroup, int log,
	bool apply, const char* attributes, const char* comment) {

	MySQL_Query_Processor_Rule_t* newQR = (MySQL_Query_Processor_Rule_t*)malloc(sizeof(MySQL_Query_Processor_Rule_t));
	newQR->rule_id = rule_id;
	newQR->active = active;
	newQR->username = (username ? strdup(username) : NULL);
	newQR->schemaname = (schemaname ? strdup(schemaname) : NULL);
	newQR->flagIN = flagIN;
	newQR->match_digest = (match_digest ? strdup(match_digest) : NULL);
	newQR->match_pattern = (match_pattern ? strdup(match_pattern) : NULL);
	newQR->negate_match_pattern = negate_match_pattern;
	newQR->re_modifiers = 0;
	{
		tokenizer_t tok;
		tokenizer(&tok, re_modifiers, ",", TOKENIZER_NO_EMPTIES);
		const char* token;
		for (token = tokenize(&tok); token; token = tokenize(&tok)) {
			if (strncasecmp(token, (char*)"CASELESS", strlen((char*)"CASELESS")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_CASELESS;
			}
			if (strncasecmp(token, (char*)"GLOBAL", strlen((char*)"GLOBAL")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_GLOBAL;
			}
		}
		free_tokenizer(&tok);
	}
	newQR->flagOUT = flagOUT;
	newQR->replace_pattern = (replace_pattern ? strdup(replace_pattern) : NULL);
	newQR->destination_hostgroup = destination_hostgroup;
	newQR->cache_ttl = cache_ttl;
	newQR->cache_empty_result = cache_empty_result;
	newQR->cache_timeout = cache_timeout;
	newQR->reconnect = reconnect;
	newQR->timeout = timeout;
	newQR->retries = retries;
	newQR->delay = delay;
	newQR->next_query_flagIN = next_query_flagIN;
	newQR->mirror_flagOUT = mirror_flagOUT;
	newQR->mirror_hostgroup = mirror_hostgroup;
	newQR->error_msg = (error_msg ? strdup(error_msg) : NULL);
	newQR->OK_msg = (OK_msg ? strdup(OK_msg) : NULL);
	newQR->sticky_conn = sticky_conn;
	newQR->multiplex = multiplex;
	newQR->gtid_from_hostgroup = gtid_from_hostgroup;
	newQR->apply = apply;
	newQR->attributes = (attributes ? strdup(attributes) : NULL);
	newQR->comment = (comment ? strdup(comment) : NULL); // see issue #643
	newQR->regex_engine1 = NULL;
	newQR->regex_engine2 = NULL;
	newQR->hits = 0;

	newQR->client_addr_wildcard_position = -1; // not existing by default
	newQR->client_addr = (client_addr ? strdup(client_addr) : NULL);
	if (newQR->client_addr) {
		char* pct = strchr(newQR->client_addr, '%');
		if (pct) { // there is a wildcard . We assume Admin did already all the input validation
			if (pct == newQR->client_addr) {
				// client_addr == '%'
				// % is at the end of the string, but also at the beginning
				// becoming a catch all
				newQR->client_addr_wildcard_position = 0;
			}
			else {
				// this math is valid also if (pct == newQR->client_addr)
				// but we separate it to clarify that client_addr_wildcard_position is a match all
				newQR->client_addr_wildcard_position = strlen(newQR->client_addr) - strlen(pct);
			}
		}
	}
	newQR->proxy_addr = (proxy_addr ? strdup(proxy_addr) : NULL);
	newQR->proxy_port = proxy_port;
	newQR->log = log;
	newQR->digest = 0;
	if (digest) {
		unsigned long long num = strtoull(digest, NULL, 0);
		if (num != ULLONG_MAX && num != 0) {
			newQR->digest = num;
		}
		else {
			proxy_error("Incorrect digest for rule_id %d : %s\n", rule_id, digest);
		}
	}
	newQR->flagOUT_weights_total = 0;
	newQR->flagOUT_ids = NULL;
	newQR->flagOUT_weights = NULL;
	if (newQR->attributes != NULL) {
		if (strlen(newQR->attributes)) {
			nlohmann::json j_attributes = nlohmann::json::parse(newQR->attributes);
			if (j_attributes.find("flagOUTs") != j_attributes.end()) {
				newQR->flagOUT_ids = new vector<int>;
				newQR->flagOUT_weights = new vector<int>;
				const nlohmann::json& flagOUTs = j_attributes["flagOUTs"];
				if (flagOUTs.type() == nlohmann::json::value_t::array) {
					for (auto it = flagOUTs.begin(); it != flagOUTs.end(); it++) {
						bool parsed = false;
						const nlohmann::json& j = *it;
						if (j.find("id") != j.end() && j.find("weight") != j.end()) {
							if (j["id"].type() == nlohmann::json::value_t::number_unsigned && j["weight"].type() == nlohmann::json::value_t::number_unsigned) {
								int id = j["id"];
								int weight = j["weight"];
								newQR->flagOUT_ids->push_back(id);
								newQR->flagOUT_weights->push_back(weight);
								newQR->flagOUT_weights_total += weight;
								parsed = true;
							}
						}
						if (parsed == false) {
							proxy_error("Failed to parse flagOUTs in JSON on attributes for rule_id %d : %s\n", newQR->rule_id, j.dump().c_str());
						}
					}
				}
				else {
					proxy_error("Failed to parse flagOUTs attributes for rule_id %d : %s\n", newQR->rule_id, flagOUTs.dump().c_str());
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Creating new rule in %p : rule_id:%d, active:%d, username=%s, schemaname=%s, flagIN:%d, %smatch_digest=\"%s\", %smatch_pattern=\"%s\", flagOUT:%d replace_pattern=\"%s\", destination_hostgroup:%d, apply:%d\n", newQR, newQR->rule_id, newQR->active, newQR->username, newQR->schemaname, newQR->flagIN, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_digest, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_pattern, newQR->flagOUT, newQR->replace_pattern, newQR->destination_hostgroup, newQR->apply);
	return newQR;
}

MySQL_Query_Processor_Rule_t* MySQL_Query_Processor::new_query_rule(const MySQL_Query_Processor_Rule_t* mqr) {

	char buf[20];
	if (mqr->digest) { // not 0
		sprintf(buf, "0x%016llX", (long long unsigned int)mqr->digest);
	}

	std::string re_mod;
	re_mod = "";
	if ((mqr->re_modifiers & QP_RE_MOD_CASELESS) == QP_RE_MOD_CASELESS) re_mod = "CASELESS";
	if ((mqr->re_modifiers & QP_RE_MOD_GLOBAL) == QP_RE_MOD_GLOBAL) {
		if (re_mod.length()) {
			re_mod = re_mod + ",";
		}
		re_mod = re_mod + "GLOBAL";
	}

	MySQL_Query_Processor_Rule_t* newQR = (MySQL_Query_Processor_Rule_t*)malloc(sizeof(MySQL_Query_Processor_Rule_t));
	newQR->rule_id = mqr->rule_id;
	newQR->active = mqr->active;
	newQR->username = (mqr->username ? strdup(mqr->username) : NULL);
	newQR->schemaname = (mqr->schemaname ? strdup(mqr->schemaname) : NULL);
	newQR->flagIN = mqr->flagIN;
	newQR->match_digest = (mqr->match_digest ? strdup(mqr->match_digest) : NULL);
	newQR->match_pattern = (mqr->match_pattern ? strdup(mqr->match_pattern) : NULL);
	newQR->negate_match_pattern = mqr->negate_match_pattern;
	newQR->re_modifiers = 0;
	{
		tokenizer_t tok;
		tokenizer(&tok, re_mod.c_str(), ",", TOKENIZER_NO_EMPTIES);
		const char* token;
		for (token = tokenize(&tok); token; token = tokenize(&tok)) {
			if (strncasecmp(token, (char*)"CASELESS", strlen((char*)"CASELESS")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_CASELESS;
			}
			if (strncasecmp(token, (char*)"GLOBAL", strlen((char*)"GLOBAL")) == 0) {
				newQR->re_modifiers |= QP_RE_MOD_GLOBAL;
			}
		}
		free_tokenizer(&tok);
	}
	newQR->flagOUT = mqr->flagOUT;
	newQR->replace_pattern = (mqr->replace_pattern ? strdup(mqr->replace_pattern) : NULL);
	newQR->destination_hostgroup = mqr->destination_hostgroup;
	newQR->cache_ttl = mqr->cache_ttl;
	newQR->cache_empty_result = mqr->cache_empty_result;
	newQR->cache_timeout = mqr->cache_timeout;
	newQR->reconnect = mqr->reconnect;
	newQR->timeout = mqr->timeout;
	newQR->retries = mqr->retries;
	newQR->delay = mqr->delay;
	newQR->next_query_flagIN = mqr->next_query_flagIN;
	newQR->mirror_flagOUT = mqr->mirror_flagOUT;
	newQR->mirror_hostgroup = mqr->mirror_hostgroup;
	newQR->error_msg = (mqr->error_msg ? strdup(mqr->error_msg) : NULL);
	newQR->OK_msg = (mqr->OK_msg ? strdup(mqr->OK_msg) : NULL);
	newQR->sticky_conn = mqr->sticky_conn;
	newQR->multiplex = mqr->multiplex;
	newQR->gtid_from_hostgroup = mqr->gtid_from_hostgroup;
	newQR->apply = mqr->apply;
	newQR->attributes = (mqr->attributes ? strdup(mqr->attributes) : NULL);
	newQR->comment = (mqr->comment ? strdup(mqr->comment) : NULL); // see issue #643
	newQR->regex_engine1 = NULL;
	newQR->regex_engine2 = NULL;
	newQR->hits = 0;

	newQR->client_addr_wildcard_position = -1; // not existing by default
	newQR->client_addr = (mqr->client_addr ? strdup(mqr->client_addr) : NULL);
	if (newQR->client_addr) {
		char* pct = strchr(newQR->client_addr, '%');
		if (pct) { // there is a wildcard . We assume Admin did already all the input validation
			if (pct == newQR->client_addr) {
				// client_addr == '%'
				// % is at the end of the string, but also at the beginning
				// becoming a catch all
				newQR->client_addr_wildcard_position = 0;
			}
			else {
				// this math is valid also if (pct == newQR->client_addr)
				// but we separate it to clarify that client_addr_wildcard_position is a match all
				newQR->client_addr_wildcard_position = strlen(newQR->client_addr) - strlen(pct);
			}
		}
	}
	newQR->proxy_addr = (mqr->proxy_addr ? strdup(mqr->proxy_addr) : NULL);
	newQR->proxy_port = mqr->proxy_port;
	newQR->log = mqr->log;
	newQR->digest = 0;
	if (mqr->digest) {
		unsigned long long num = strtoull(buf, NULL, 0);
		if (num != ULLONG_MAX && num != 0) {
			newQR->digest = num;
		}
		else {
			proxy_error("Incorrect digest for rule_id %d : %s\n", mqr->rule_id, buf);
		}
	}
	newQR->flagOUT_weights_total = 0;
	newQR->flagOUT_ids = NULL;
	newQR->flagOUT_weights = NULL;
	if (newQR->attributes != NULL) {
		if (strlen(newQR->attributes)) {
			nlohmann::json j_attributes = nlohmann::json::parse(newQR->attributes);
			if (j_attributes.find("flagOUTs") != j_attributes.end()) {
				newQR->flagOUT_ids = new vector<int>;
				newQR->flagOUT_weights = new vector<int>;
				const nlohmann::json& flagOUTs = j_attributes["flagOUTs"];
				if (flagOUTs.type() == nlohmann::json::value_t::array) {
					for (auto it = flagOUTs.begin(); it != flagOUTs.end(); it++) {
						bool parsed = false;
						const nlohmann::json& j = *it;
						if (j.find("id") != j.end() && j.find("weight") != j.end()) {
							if (j["id"].type() == nlohmann::json::value_t::number_unsigned && j["weight"].type() == nlohmann::json::value_t::number_unsigned) {
								int id = j["id"];
								int weight = j["weight"];
								newQR->flagOUT_ids->push_back(id);
								newQR->flagOUT_weights->push_back(weight);
								newQR->flagOUT_weights_total += weight;
								parsed = true;
							}
						}
						if (parsed == false) {
							proxy_error("Failed to parse flagOUTs in JSON on attributes for rule_id %d : %s\n", newQR->rule_id, j.dump().c_str());
						}
					}
				}
				else {
					proxy_error("Failed to parse flagOUTs attributes for rule_id %d : %s\n", newQR->rule_id, flagOUTs.dump().c_str());
				}
			}
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Creating new rule in %p : rule_id:%d, active:%d, username=%s, schemaname=%s, flagIN:%d, %smatch_digest=\"%s\", %smatch_pattern=\"%s\", flagOUT:%d replace_pattern=\"%s\", destination_hostgroup:%d, apply:%d\n", newQR, newQR->rule_id, newQR->active, newQR->username, newQR->schemaname, newQR->flagIN, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_digest, (newQR->negate_match_pattern ? "(!)" : ""), newQR->match_pattern, newQR->flagOUT, newQR->replace_pattern, newQR->destination_hostgroup, newQR->apply);
	return newQR;
}

SQLite3_result* MySQL_Query_Processor::get_current_query_rules() {
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping current query rules, using Global version %d\n", version);
	SQLite3_result* result = new SQLite3_result(36);
	MySQL_Query_Processor_Rule_t* qr1;
	rdlock();
	result->add_column_definition(SQLITE_TEXT, "rule_id");
	result->add_column_definition(SQLITE_TEXT, "active");
	result->add_column_definition(SQLITE_TEXT, "username");
	result->add_column_definition(SQLITE_TEXT, "schemaname");
	result->add_column_definition(SQLITE_TEXT, "flagIN");
	result->add_column_definition(SQLITE_TEXT, "client_addr");
	result->add_column_definition(SQLITE_TEXT, "proxy_addr");
	result->add_column_definition(SQLITE_TEXT, "proxy_port");
	result->add_column_definition(SQLITE_TEXT, "digest");
	result->add_column_definition(SQLITE_TEXT, "match_digest");
	result->add_column_definition(SQLITE_TEXT, "match_pattern");
	result->add_column_definition(SQLITE_TEXT, "negate_match_pattern");
	result->add_column_definition(SQLITE_TEXT, "re_modifiers");
	result->add_column_definition(SQLITE_TEXT, "flagOUT");
	result->add_column_definition(SQLITE_TEXT, "replace_pattern");
	result->add_column_definition(SQLITE_TEXT, "destination_hostgroup");
	result->add_column_definition(SQLITE_TEXT, "cache_ttl");
	result->add_column_definition(SQLITE_TEXT, "cache_empty_result");
	result->add_column_definition(SQLITE_TEXT, "cache_timeout");
	result->add_column_definition(SQLITE_TEXT, "reconnect");
	result->add_column_definition(SQLITE_TEXT, "timeout");
	result->add_column_definition(SQLITE_TEXT, "retries");
	result->add_column_definition(SQLITE_TEXT, "delay");
	result->add_column_definition(SQLITE_TEXT, "next_query_flagIN");
	result->add_column_definition(SQLITE_TEXT, "mirror_flagOUT");
	result->add_column_definition(SQLITE_TEXT, "mirror_hostgroup");
	result->add_column_definition(SQLITE_TEXT, "error_msg");
	result->add_column_definition(SQLITE_TEXT, "OK_msg");
	result->add_column_definition(SQLITE_TEXT, "sticky_conn");
	result->add_column_definition(SQLITE_TEXT, "multiplex");
	result->add_column_definition(SQLITE_TEXT, "gtid_from_hostgroup");
	result->add_column_definition(SQLITE_TEXT, "log");
	result->add_column_definition(SQLITE_TEXT, "apply");
	result->add_column_definition(SQLITE_TEXT, "attributes");
	result->add_column_definition(SQLITE_TEXT, "comment"); // issue #643
	result->add_column_definition(SQLITE_TEXT, "hits");
	for (std::vector<QP_rule_t*>::iterator it = rules.begin(); it != rules.end(); ++it) {
		qr1 = static_cast<MySQL_Query_Processor_Rule_t*>(*it);
		MySQL_Rule_Text* qt = new MySQL_Rule_Text(qr1);
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Dumping Query Rule id: %d\n", qr1->rule_id);
		result->add_row(qt->pta);
		delete qt;
	}
	wrunlock();
	return result;
}

void MySQL_Query_Processor::update_tdigest_configuration() {
	if (latency_tracker && GloMTH) {
		// Get configuration from MySQL global variables (thread-safe)
		bool enabled = GloMTH->get_variable_int("command_latency_tracking_enabled") != 0;
		const char* quantiles_str = GloMTH->get_variable_string("command_latency_tracking_quantiles");
		int compression = GloMTH->get_variable_int("command_latency_tracking_compression");
		int max_centroids = GloMTH->get_variable_int("command_latency_tracking_max_centroids");
		int max_unmerged = GloMTH->get_variable_int("command_latency_tracking_max_unmerged");
		
		// Update tracker configuration
		latency_tracker->update_configuration(enabled, quantiles_str, 
											compression, max_centroids, max_unmerged);
	}
}

SQLite3_result* MySQL_Query_Processor::get_stats_tdigest_config() {
	SQLite3_result* result = new SQLite3_result(3);
	result->add_column_definition(SQLITE_TEXT, "Variable_name");
	result->add_column_definition(SQLITE_TEXT, "Value");
	result->add_column_definition(SQLITE_TEXT, "Description");
	
	// Helper lambda for safe row addition
	auto add_config_row = [&result](const char* var_name, const char* value, const char* description) {
		char** pta = new char*[3];
		pta[0] = strdup(var_name);
		pta[1] = strdup(value);
		pta[2] = strdup(description);
		result->add_row(pta);
		// SQLite3_result takes ownership, so we free the array but not the strings
		delete[] pta;
	};
	
	// T-Digest enabled status
	add_config_row("command_latency_tracking_enabled",
				  mysql_thread___command_latency_tracking_enabled ? "true" : "false",
				  "Enable/disable t-digest latency tracking");
	
	// Configured quantiles
	add_config_row("command_latency_tracking_quantiles",
				  mysql_thread___command_latency_tracking_quantiles,
				  "Comma-separated list of quantiles to track (e.g., 0.5,0.95,0.99)");
	
	// Compression factor
	char compression_str[64];
	double compression = mysql_thread___command_latency_tracking_compression / 100.0;
	snprintf(compression_str, sizeof(compression_str), "%.2f", compression);
	add_config_row("command_latency_tracking_compression",
				  compression_str,
				  "T-digest compression factor (higher = more accurate, more memory)");
	
	// Max centroids
	char centroids_str[32];
	snprintf(centroids_str, sizeof(centroids_str), "%d", mysql_thread___command_latency_tracking_max_centroids);
	add_config_row("command_latency_tracking_max_centroids",
				  centroids_str,
				  "Maximum number of centroids per t-digest");
	
	// Max unmerged
	char unmerged_str[32];
	snprintf(unmerged_str, sizeof(unmerged_str), "%d", mysql_thread___command_latency_tracking_max_unmerged);
	add_config_row("command_latency_tracking_max_unmerged",
				  unmerged_str,
				  "Maximum unmerged buffer size before compression");
	
	// Current status if tracker exists
	if (latency_tracker) {
		add_config_row("current_status",
					  latency_tracker->is_enabled() ? "enabled" : "disabled",
					  "Current operational status of t-digest tracking");
		
		// Current configured quantiles  
		std::vector<double> quantiles = latency_tracker->get_configured_quantiles();
		std::ostringstream quantiles_oss;
		for (size_t i = 0; i < quantiles.size(); ++i) {
			if (i > 0) quantiles_oss << ",";
			quantiles_oss << quantiles[i];
		}
		
		add_config_row("active_quantiles",
					  quantiles_oss.str().c_str(),
					  "Currently active quantiles parsed from configuration");
	}
	
	return result;
}
