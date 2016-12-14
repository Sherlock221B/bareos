/*
   BAREOS® - Backup Archiving REcovery Open Sourced

   Copyright (C) 2013-2014 Planets Communications B.V.
   Copyright (C) 2013-2014 Bareos GmbH & Co. KG

   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation, which is
   listed in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.
*/
/*
 * Storage Daemon plugin that handles automatic deduplication of the data.
 *
 * Sébastien Marchal, December 2016
 */
#include "bareos.h"
#include "stored.h"

#include "deduplib/blake2/blake2.h"

#include "deduplib/rabin-fingerprint/rabin_polynomial.h"
#include "deduplib/rabin-fingerprint/rabin_polynomial_constants.h"

#include <inttypes.h>

#include <sqlite3.h>

#include <sys/types.h>
#include <sys/stat.h>

#define PLUGIN_LICENSE      "Bareos AGPLv3"
#define PLUGIN_AUTHOR       "Sébastien Marchal"
#define PLUGIN_DATE         "December 2016"
#define PLUGIN_VERSION      "1"
#define PLUGIN_DESCRIPTION  "Deduplication Storage Daemon Plugin"
#define PLUGIN_USAGE        "dedup:path=<path-to-dedup-volume>:prefix=<prefix-used-by-dedup-volume>:group_prefix=<prefix-used-to-group-dedup-volume>:variable_block=<true-or-false>"

#define Dmsg(context, level,  ...) bfuncs->DebugMessage(context, __FILE__, __LINE__, level, __VA_ARGS__ )
#define Jmsg(context, type,  ...) bfuncs->JobMessage(context, __FILE__, __LINE__, type, 0, __VA_ARGS__ )


/*
 * Forward referenced functions
 */
static bRC newPlugin(bpContext *ctx);
static bRC freePlugin(bpContext *ctx);
static bRC getPluginValue(bpContext *ctx, psdVariable var, void *value);
static bRC setPluginValue(bpContext *ctx, psdVariable var, void *value);
static bRC handlePluginEvent(bpContext *ctx, bsdEvent *event, void *value);
static bRC handleJobStart(bpContext *ctx);
static bRC handleJobEnd(bpContext *ctx);
static bRC handleVolumeLoad(bpContext *ctx, void *value);
static bRC setup_record_translation(bpContext *ctx, void *value);
static bRC handle_read_translation(bpContext *ctx, void *value);
static bRC handle_write_translation(bpContext *ctx, void *value);
static bRC parse_plugin_definition(bpContext *ctx, void *value);

/*
 * Is the SD in compatible mode or not.
 */
static bool sd_enabled_compatible = false;

/*
 * Pointers to Bareos functions
 */
static bsdFuncs *bfuncs = NULL;
static bsdInfo *binfo = NULL;

static genpInfo pluginInfo = {
   sizeof(pluginInfo),
   SD_PLUGIN_INTERFACE_VERSION,
   SD_PLUGIN_MAGIC,
   PLUGIN_LICENSE,
   PLUGIN_AUTHOR,
   PLUGIN_DATE,
   PLUGIN_VERSION,
   PLUGIN_DESCRIPTION,
   PLUGIN_USAGE
};

static psdFuncs pluginFuncs = {
   sizeof(pluginFuncs),
   SD_PLUGIN_INTERFACE_VERSION,

   /*
    * Entry points into plugin
    */
   newPlugin,        /* new plugin instance */
   freePlugin,       /* free plugin instance */
   getPluginValue,
   setPluginValue,
   handlePluginEvent
};

/*
 * Plugin arguments
 * This defines the arguments that the plugin parser understands.
 */
enum plugin_argument_type {
   argument_none,
   argument_dedup_volume_path,
   argument_dedup_volume_prefix,
   argument_dedup_volume_group_prefix,
   argument_variable_block_dedup
};

struct plugin_argument {
   const char *name;
   enum plugin_argument_type type;
};

static plugin_argument plugin_arguments[] = {
   { "path", argument_dedup_volume_path },
   { "prefix", argument_dedup_volume_prefix },
   { "group_prefix", argument_dedup_volume_group_prefix },
   { "variable_block", argument_variable_block_dedup },
   { NULL, argument_none }
};

/*
 * Plugin constant
 */
#define PREFIX_SEPARATOR "|"

#define SEGMENT_SIZE 10485760

#define MAX_MANIFEST_LINE_LENGTH 32

#define MAX_BLOCK_DB 9999999
#define MAX_BLOCK_DB_SIZE 53687091200

#define MIN_BLOCK_SIZE 4096
#define AVG_BLOCK_SIZE 8192
#define MAX_BLOCK_SIZE 16384

#define FIXED_BLOCK_SIZE 65536;

/*
 * Plugin structure
 */
typedef struct SESSION_INFO {
   uint32_t vol_session_id;
   uint32_t vol_session_time;
   sqlite3_int64 id;
   int32_t file_index;
   uint32_t record_len;
} SESSION_INFO;

typedef struct BLOCK_DB {
   sqlite3_int64 id;
   sqlite3 *db;
   sqlite3 *digest_db;
   sqlite3_int64 size;
   bool db_transaction_in_progress;
   bool digest_db_transaction_in_progress;
   BLOCK_DB *next;
} BLOCK_DB;

typedef struct MANIFEST_FILE {
   sqlite3_int64 id;
   FILE *file;
   char last_line[MAX_MANIFEST_LINE_LENGTH];
} MANIFEST_FILE;

typedef struct BLOCK_INFO {
   sqlite3_int64 block_db_id;
   sqlite3_int64 block_id;
   unsigned char digest[32];
   BLOCK_INFO *left, *right;
} BLOCK_INFO;

typedef struct DEDUP_VOLUME {
   char *volume_name;
   char *path;
   sqlite3 *catalog_db;
   bool catalog_db_transaction_in_progress;
   BLOCK_DB *block_db_list;
   BLOCK_INFO *block_info_tree;
   SESSION_INFO read_session;
   SESSION_INFO write_session;
   MANIFEST_FILE read_manifest;
   MANIFEST_FILE write_manifest;
   bool first_read;
   bool first_write;
   DEDUP_VOLUME *next;
} DEDUP_VOLUME;

/*
 * Plugin private context
 */
struct plugin_ctx {
   char *dedup_volume_path;           /* Path of the dedup volume */
   char *dedup_volume_prefix;         /* Prefix used by dedup volume */
   char *dedup_volume_group_prefix;   /* Prefix used to group dedup volume */
   bool variable_block_dedup;         /* Type of deduplication */
   DEDUP_VOLUME *dedup_volume_list;   /* List of dedup volume */
};


/*
 * Plugin function
 */
static bool write_dedup_record(bpContext *ctx, DCR *dcr);
static bool read_dedup_record(bpContext *ctx, DCR *dcr);

static bool check_dedup_volume_name(char *volume_name, char *dedup_volume_prefix);

static bool get_dedup_volume(DEDUP_VOLUME *dedup_volume_list, char *volume_name, char *dedup_volume_group_prefix, DEDUP_VOLUME *&dedup_volume);
static bool add_dedup_volume(DEDUP_VOLUME *&dedup_volume_list, char *volume_name, char *dedup_volume_path, char *dedup_volume_group_prefix, DEDUP_VOLUME *&dedup_volume);
static bool free_dedup_volume(bpContext *ctx, DEDUP_VOLUME *&dedup_volume);

static bool load_block_db_list(bpContext *ctx, DEDUP_VOLUME *&dedup_volume);
static bool free_block_db(BLOCK_DB *&block_db);

static bool load_block_info_tree(bpContext *ctx, DEDUP_VOLUME *&dedup_volume);

static bool get_block_info(BLOCK_INFO *block_info_tree, unsigned char *digest, BLOCK_INFO **&block_info);
static bool free_block_info(BLOCK_INFO *&block_info);

static bool dedup_record(bpContext *ctx, DEDUP_VOLUME *&dedup_volume, MANIFEST_FILE &manifest, DEV_RECORD *rec);
static bool load_record(bpContext *ctx, DEDUP_VOLUME *&dedup_volume, DEV_RECORD *rec);

static bool add_block(bpContext *ctx, DEDUP_VOLUME *dedup_volume, char *block, uint32_t block_len, unsigned char *digest, sqlite3_int64 &block_db_id, sqlite3_int64 &block_id);

/*
 * File function
 */
static mode_t get_umask();
static bool create_directory(char *path);

/*
 * DB function
 */
static bool open_catalog_db(char *dedup_volume_path, char *dedup_volume_name, sqlite3 *&catalog_db);
static bool open_block_db(char *dedup_volume_path, char *dedup_volume_name, sqlite3_int64 block_db_id, sqlite3 *&block_db);
static bool open_digest_db(char *dedup_volume_path, char *dedup_volume_name, sqlite3_int64 digest_db_id, sqlite3 *&digest_db);
static bool close_db(sqlite3 *&db);
static bool begin_transaction(sqlite3 *&db);
static bool end_transaction(sqlite3 *&db);

/*
 * Catalog DB function
 */
static bool cdb_add_session(sqlite3 *&catalog_db, uint32_t volSessionId, uint32_t volSessionTime, sqlite3_int64 &session_id);
static bool cdb_add_block_db(sqlite3 *&catalog_db, sqlite3_int64 &block_db_id);
static bool cdb_delete_session(sqlite3 *&catalog_db, uint32_t volSessionId, uint32_t volSessionTime);
static bool cdb_get_session_id(sqlite3 *&catalog_db, uint32_t volSessionId, uint32_t volSessionTime, sqlite3_int64 &session_id);
static bool cdb_block_db_exist(sqlite3 *&catalog_db, sqlite3_int64 block_db_id, bool &exist);

/*
 * Block DB function
 */
static bool bdb_add_block(sqlite3 *&block_db, char *block, uint32_t block_len, sqlite3_int64 &block_id);
static bool bdb_get_block(sqlite3 *&block_db, sqlite3_int64 block_id, char *&block, sqlite3_int64 &block_len);
static bool bdb_get_page_count(sqlite3 *&db, sqlite3_int64 &page_count);

/*
 * Digest DB function
 */
static bool ddb_add_digest(sqlite3 *&digest_db, sqlite3_int64 block_id, unsigned char *digest);

/*
 * Manifest File function
 */
static bool open_manifest_file(char *dedup_volume_path, char *dedup_volume_name, sqlite3_int64 session_id, char mode, MANIFEST_FILE &manifest);
static bool close_manifest_file(MANIFEST_FILE &manifest);
static bool mf_add_file(MANIFEST_FILE &manifest, int32_t fileIndex, int32_t stream);
static bool mf_add_record_len(MANIFEST_FILE &manifest, uint32_t record_len);
static bool mf_add_block(MANIFEST_FILE &manifest, sqlite3_int64 block_db_id, sqlite3_int64 block_id);
static bool mf_goto_file(MANIFEST_FILE &manifest, int32_t fileIndex, int32_t stream);
static bool mf_get_record_len(MANIFEST_FILE &manifest, uint32_t &record_len);
static bool mf_get_block(MANIFEST_FILE &manifest, sqlite3_int64 &block_db_id, sqlite3_int64 &block_id);


static int const dbglvl = 200;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * loadPlugin() and unloadPlugin() are entry points that are
 *  exported, so Bareos can directly call these two entry points
 *  they are common to all Bareos plugins.
 *
 * External entry point called by Bareos to "load the plugin
 */
bRC DLL_IMP_EXP loadPlugin(bsdInfo *lbinfo,
                           bsdFuncs *lbfuncs,
                           genpInfo **pinfo,
                           psdFuncs **pfuncs)
{
   bfuncs = lbfuncs;       /* set Bareos funct pointers */
   binfo  = lbinfo;
   *pinfo  = &pluginInfo;  /* return pointer to our info */
   *pfuncs = &pluginFuncs; /* return pointer to our functions */

   /*
    * Get the current setting of the compatible flag.
    */
   bfuncs->getBareosValue(NULL, bsdVarCompatible, (void *)&sd_enabled_compatible);

   return bRC_OK;
}

/*
 * External entry point to unload the plugin
 */
bRC DLL_IMP_EXP unloadPlugin()
{
   return bRC_OK;
}

#ifdef __cplusplus
}
#endif

/*
 * The following entry points are accessed through the function
 * pointers we supplied to Bareos. Each plugin type (dir, fd, sd)
 * has its own set of entry points that the plugin must define.
 *
 * Create a new instance of the plugin i.e. allocate our private storage
 */
static bRC newPlugin(bpContext *ctx)
{
   int JobId = 0;
   struct plugin_ctx *p_ctx;
   
   bfuncs->getBareosValue(ctx, bsdVarJobId, (void *)&JobId);
   Dmsg(ctx, dbglvl, "dedup-sd: newPlugin JobId=%d\n", JobId);

   p_ctx = (struct plugin_ctx *)malloc(sizeof(struct plugin_ctx));
   if (!p_ctx) {
      return bRC_Error;
   }

   p_ctx->dedup_volume_path = NULL;
   p_ctx->dedup_volume_prefix = NULL;
   p_ctx->dedup_volume_group_prefix = NULL;
   p_ctx->variable_block_dedup = false;
   p_ctx->dedup_volume_list = NULL;

   memset(p_ctx, 0, sizeof(struct plugin_ctx));
   ctx->pContext = (void *)p_ctx;        /* set our context pointer */

   /*
    * Only register plugin events we are interested in.
    *
    * bsdEventJobEnd - SD Job finished.
    * bsdEventSetupRecordTranslation - Setup the buffers for doing record translation.
    * bsdEventReadRecordTranslation - Perform read-side record translation.
    * bsdEventWriteRecordTranslation - Perform write-side record translantion.
    */
   bfuncs->registerBareosEvents(ctx,
                                7,
                                bsdEventNewPluginOptions,
                                bsdEventJobStart,
                                bsdEventJobEnd,
                                bsdEventVolumeLoad,
                                bsdEventSetupRecordTranslation,
                                bsdEventReadRecordTranslation,
                                bsdEventWriteRecordTranslation);

   return bRC_OK;
}

/*
 * Free a plugin instance, i.e. release our private storage
 */
static bRC freePlugin(bpContext *ctx)
{
   int JobId = 0;
   DEDUP_VOLUME *dedup_volume;
         
   struct plugin_ctx *p_ctx = (struct plugin_ctx *)ctx->pContext;

   bfuncs->getBareosValue(ctx, bsdVarJobId, (void *)&JobId);
   Dmsg(ctx, dbglvl, "dedup-sd: freePlugin JobId=%d\n", JobId);

   if (!p_ctx) {
      return bRC_Error;
   }

   dedup_volume = p_ctx->dedup_volume_list;
   free_dedup_volume(ctx, dedup_volume);
   p_ctx->dedup_volume_list = NULL;
      
   if (p_ctx) {
      if(p_ctx->dedup_volume_path) 
      { 
         free(p_ctx->dedup_volume_path);
         p_ctx->dedup_volume_path = NULL; 
      }
      if(p_ctx->dedup_volume_prefix) 
      { 
         free(p_ctx->dedup_volume_prefix); 
         p_ctx->dedup_volume_prefix = NULL;
      }
      if(p_ctx->dedup_volume_group_prefix) 
      { 
         free(p_ctx->dedup_volume_group_prefix);
         p_ctx->dedup_volume_group_prefix = NULL; 
      }
      free(p_ctx);
   }
   ctx->pContext = NULL;

   return bRC_OK;
}

/*
 * Return some plugin value (none defined)
 */
static bRC getPluginValue(bpContext *ctx, psdVariable var, void *value)
{
   Dmsg(ctx, dbglvl, "dedup-sd: getPluginValue var=%d\n", var);

   return bRC_OK;
}

/*
 * Set a plugin value (none defined)
 */
static bRC setPluginValue(bpContext *ctx, psdVariable var, void *value)
{
   Dmsg(ctx, dbglvl, "dedup-sd: setPluginValue var=%d\n", var);

   return bRC_OK;
}

/*
 * Handle an event that was generated in Bareos
 */
static bRC handlePluginEvent(bpContext *ctx, bsdEvent *event, void *value)
{
   switch (event->eventType) {
   case bsdEventSetupRecordTranslation:
      return setup_record_translation(ctx, value);
   case bsdEventReadRecordTranslation:
      return handle_read_translation(ctx, value);
   case bsdEventWriteRecordTranslation:
      return handle_write_translation(ctx, value);
   case bsdEventJobStart:
      return handleJobStart(ctx);
   case bsdEventJobEnd:
      return handleJobEnd(ctx);
   case bsdEventVolumeLoad:
      return handleVolumeLoad(ctx, value);
   case bsdEventNewPluginOptions:
      return parse_plugin_definition(ctx, value);
   default:
      Dmsg(ctx, dbglvl, "dedup-sd: handlePluginEvent unknown event %d\n", event->eventType);
      return bRC_Error;
   }

   return bRC_OK;
}

/*
 * Strip any backslashes in the string.
 */
static inline void strip_back_slashes(char *value)
{
   char *bp;

   bp = value;
   while (*bp) {
      switch (*bp) {
      case '\\':
         bstrinlinecpy(bp, bp + 1);
         break;
      default:
         break;
      }

      bp++;
   }
}

/*
 * Parse a integer value.
 */
static inline int64_t parse_integer(const char *argument_value)
{
   return str_to_int64(argument_value);
}

/*
 * Parse a boolean value e.g. check if its yes or true anything else translates to false.
 */
static inline bool parse_boolean(const char *argument_value)
{
   if (bstrcasecmp(argument_value, "yes") ||
       bstrcasecmp(argument_value, "true")) {
      return true;
   } else {
      return false;
   }
}

/*
 * Always set destination to value and clean any previous one.
 */
static inline void set_string(char **destination, char *value)
{
   if (*destination) {
      free(*destination);
   }

   *destination = bstrdup(value);
   strip_back_slashes(*destination);
}

/*
 * Parse the plugin definition passed in.
 *
 * The definition is in this form:
 *
 * dedup:path=<path-to-dedup-volume>:prefix=<prefix-used-by-dedup-volume>:prefix_group=<prefix-used-to-group-dedup-volume>:variable_block=<true-or-false>:verify=<true-or-false>
 */
static bRC parse_plugin_definition(bpContext *ctx, void *value)
{
   int i;
   POOL_MEM plugin_definition(PM_FNAME);
   char *bp, *argument, *argument_value;
   plugin_ctx *p_ctx = (plugin_ctx *)ctx->pContext;

   if (!value) {
      return bRC_Error;
   }

   /*
    * Parse the plugin definition.
    * Make a private copy of the whole string.
    */
   pm_strcpy(plugin_definition, (char *)value);

   bp = strchr(plugin_definition.c_str(), ':');
   if (!bp) {
      Jmsg(ctx, M_FATAL, "dedup-sd: Illegal plugin definition %s\n", plugin_definition.c_str());
      Dmsg(ctx, dbglvl, "dedup-sd: Illegal plugin definition %s\n", plugin_definition.c_str());
      goto bail_out;
   }

   /*
    * Skip the first ':'
    */
   bp++;

   while (bp) {
      if (strlen(bp) == 0) {
         break;
      }

      /*
       * Each argument is in the form:
       *    <argument> = <argument_value>
       *
       * So we setup the right pointers here, argument to the beginning
       * of the argument, argument_value to the beginning of the argument_value.
       */
      argument = bp;
      argument_value = strchr(bp, '=');
      if (!argument_value) {
         Jmsg(ctx, M_FATAL, "dedup-sd: Illegal argument %s without value\n", argument);
         Dmsg(ctx, dbglvl, "dedup-sd: Illegal argument %s without value\n", argument);
         goto bail_out;
      }
      *argument_value++ = '\0';

      /*
       * See if there are more arguments and setup for the next run.
       */
      bp = argument_value;
      do {
         bp = strchr(bp, ':');
         if (bp) {
            if (*(bp - 1) != '\\') {
               *bp++ = '\0';
               break;
            } else {
               bp++;
            }
         }
      } while (bp);

      for (i = 0; plugin_arguments[i].name; i++) {
         if (bstrcasecmp(argument, plugin_arguments[i].name)) {
            int64_t *int_destination = NULL;
            char **str_destination = NULL;
            bool *bool_destination = NULL;

            switch (plugin_arguments[i].type) {
            case argument_dedup_volume_path:
               str_destination = &p_ctx->dedup_volume_path;
               break;
            case argument_dedup_volume_prefix:
               str_destination = &p_ctx->dedup_volume_prefix;
               break;
            case argument_dedup_volume_group_prefix:
               str_destination = &p_ctx->dedup_volume_group_prefix;
               break;
            case argument_variable_block_dedup:
               bool_destination = &p_ctx->variable_block_dedup;
               break;
            
            default:
               break;
            }

            if (int_destination) {
               *int_destination = parse_integer(argument_value);
            }

            if (str_destination) {
               set_string(str_destination, argument_value);
            }

            if (bool_destination) {
               *bool_destination = parse_boolean(argument_value);
            }

            /*
             * When we have a match break the loop.
             */
            break;
         }
      }

   }

   Dmsg(ctx, dbglvl, "dedup-sd: Value of argument path=%s\n", p_ctx->dedup_volume_path);
   Dmsg(ctx, dbglvl, "dedup-sd: Value of argument prefix=%s\n", p_ctx->dedup_volume_prefix);
   Dmsg(ctx, dbglvl, "dedup-sd: Value of argument group_prefix=%s\n", p_ctx->dedup_volume_group_prefix);
   Dmsg(ctx, dbglvl, "dedup-sd: Value of argument variable_block=%d\n", p_ctx->variable_block_dedup);

   /*
    * path argument is required
    */
   if (!p_ctx->dedup_volume_path) {
      Jmsg(ctx, M_FATAL, "dedup-sd: Argument path not set\n");
      Dmsg(ctx, dbglvl, "dedup-sd: Argument path not set\n");
      goto bail_out;
   }

   /*
    * prefix argument is required
    */
   if (!p_ctx->dedup_volume_prefix) {
      Jmsg(ctx, M_FATAL, "dedup-sd: Argument prefix not set\n");
      Dmsg(ctx, dbglvl, "dedup-sd: Argument prefix not set\n");
      goto bail_out;
   }

   return bRC_OK;

bail_out:
   return bRC_Error;
}

/*
 * At start of job.
 */
static bRC handleJobStart(bpContext *ctx)
{
   return bRC_OK;
}

/*
 * At end of job.
 */
static bRC handleJobEnd(bpContext *ctx)
{
   return bRC_OK;
}

/*
 * At load of volume open the database.
 */
static bRC handleVolumeLoad(bpContext *ctx, void *value)
{
   DCR *dcr;
   struct plugin_ctx *p_ctx = (struct plugin_ctx *)ctx->pContext;

   /*
    * Unpack the arguments passed in.
    */
   dcr = (DCR *)value;
   if (!dcr) {
      return bRC_Error;
   }

   if (!p_ctx) {
      return bRC_Error;
   }

   /* Check device type */
   if(dcr->dev->is_file())
   {
      /* Check volume name */
      if(check_dedup_volume_name(dcr->VolumeName, p_ctx->dedup_volume_prefix))
      {

         Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad DCR VolumeName=%s\n", dcr->VolumeName);
   
         DEDUP_VOLUME *dedup_volume = NULL;

         /* Get or add dedup_volume in dedup_volume_list */
         if(!get_dedup_volume(p_ctx->dedup_volume_list, dcr->VolumeName, p_ctx->dedup_volume_group_prefix, dedup_volume)) 
         {
            add_dedup_volume(p_ctx->dedup_volume_list, dcr->VolumeName, p_ctx->dedup_volume_path, p_ctx->dedup_volume_group_prefix, dedup_volume);
            Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad add_dedup_volume VolumeName=%s\n", dedup_volume->volume_name);
            if(create_directory(dedup_volume->path)) Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad create_directory Path=%s\n", dedup_volume->path);
            else {
               Jmsg(ctx, M_FATAL, "dedup-sd: volumeLoad can not create directory Path=%s\n", dedup_volume->path);
               Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad can not create directory Path=%s\n", dedup_volume->path);
               return bRC_Error;
            }
         }
         else Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad get_dedup_volume VolumeName=%s already in dedup_volume_list\n", dcr->VolumeName);

         /* Open catalog_db */
         if(!dedup_volume->catalog_db)
         {
            if(open_catalog_db(dedup_volume->path, dedup_volume->volume_name, dedup_volume->catalog_db) == false) {
               Jmsg(ctx, M_FATAL, "dedup-sd: volumeLoad can not open catalog database %s\n", dedup_volume->volume_name);
               Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad can not open catalog database %s\n", dedup_volume->volume_name);
               return bRC_Error;
            }
            else Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad open catalog database %s\n", dedup_volume->volume_name);
         }

         /* Load block_db_list */
         if(!dedup_volume->block_db_list)
         {
            if(load_block_db_list(ctx, dedup_volume) == false) {
               Jmsg(ctx, M_FATAL, "dedup-sd: volumeLoad can not load block database %s\n", dedup_volume->volume_name);
               Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad can not load block database %s\n", dedup_volume->volume_name);
               return bRC_Error;
            }
         }
      }
      else
      {
         Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad VolumeName=%s is not a dedup volume\n", dcr->VolumeName);
      }
   }
   else
   {
      Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad DeviceName=%s is not a file\n", dcr->dev->print_name());
   }

   return bRC_OK;
}

static bRC setup_record_translation(bpContext *ctx, void *value)
{
   DCR *dcr;
   
   /*
    * Unpack the arguments passed in.
    */
   dcr = (DCR *)value;
   if (!dcr) {
      return bRC_Error;
   }

   JCR *jcr = dcr->jcr;
   Dmsg(ctx, dbglvl, "dedup-sd: setup_record_translation jcr->buf_size=%d\n", jcr->buf_size);
   if (jcr->buf_size == 0) {
      jcr->buf_size = DEFAULT_NETWORK_BUFFER_SIZE;
   }

   return bRC_OK;
}

static bRC handle_read_translation(bpContext *ctx, void *value)
{
   DCR *dcr;
   struct plugin_ctx *p_ctx = (struct plugin_ctx *)ctx->pContext;

   bool swap_record = false;

   /*
    * Unpack the arguments passed in.
    */
   dcr = (DCR *)value;
   if (!dcr) {
      return bRC_Error;
   }

   if (!p_ctx) {
      return bRC_Error;
   }

   /* Check device type */
   if(dcr->dev->is_file())
   {
      /* Check volume name */
      if(check_dedup_volume_name(dcr->VolumeName, p_ctx->dedup_volume_prefix))
      {
         /* Read dedup record */
         swap_record = read_dedup_record(ctx, dcr);

         if(!swap_record) {
            return bRC_Error;
         }
      }
      else
      {
         Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad VolumeName=%s is not a dedup volume\n", dcr->VolumeName);
      }
   }
   else
   {
      Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad DeviceName=%s is not a file\n", dcr->dev->print_name());
   }
   
   return bRC_OK;
}

static bRC handle_write_translation(bpContext *ctx, void *value)
{
   DCR *dcr;
   struct plugin_ctx *p_ctx = (struct plugin_ctx *)ctx->pContext;
   
   bool swap_record = false;

   /*
    * Unpack the arguments passed in.
    */
   dcr = (DCR *)value;
   if (!dcr) {
      return bRC_Error;
   }

   if (!p_ctx) {
      return bRC_Error;
   }

   /* Check device type */
   if(dcr->dev->is_file())
   {
      /* Check volume name */
      if(check_dedup_volume_name(dcr->VolumeName, p_ctx->dedup_volume_prefix))
      {
         /* Write dedup record */
         swap_record = write_dedup_record(ctx, dcr);

         if(!swap_record) {
            return bRC_Error;
         }
      }
      else
      {
         Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad VolumeName=%s is not a dedup volume\n", dcr->VolumeName);
      }
   }
   else
   {
      Dmsg(ctx, dbglvl, "dedup-sd: volumeLoad DeviceName=%s is not a file\n", dcr->dev->print_name());
   }

   return bRC_OK;
}


/*
 * Perform automatic dedup of certain stream types when enabled in the config.
 */
static bool write_dedup_record(bpContext *ctx, DCR *dcr)
{
   bool retval = false;
   
   /* Bareos Record */
   DEV_RECORD *rec, *nrec;
   bool intermediate_value = false;
   
   /* Dedup volume and block db */
   DEDUP_VOLUME *dedup_volume = NULL;
   BLOCK_DB *block_db = NULL;
      
   struct plugin_ctx *p_ctx = (struct plugin_ctx *)ctx->pContext;

   /*
    * See what our starting point is. When dcr->after_rec is set we already have
    * a translated record by another SD plugin. Then we use that translated record
    * as the starting point otherwise we start at dcr->before_rec. When an earlier
    * translation already happened we can free that record when we have a success
    * full translation here as that record is of no use anymore.
    */
   if (dcr->after_rec) {
      rec = dcr->after_rec;
      intermediate_value = true;
   } else {
      rec = dcr->before_rec;
   }

   /*
    * We only do dedup for the following stream types:
    *
    * - STREAM_FILE_DATA
    * - STREAM_WIN32_DATA
    * - STREAM_SPARSE_DATA
    * - STREAM_ENCRYPTED_FILE_DATA
    * - STREAM_ENCRYPTED_WIN32_DATA
    */
   switch (rec->maskedStream) {
   case STREAM_FILE_DATA:
   case STREAM_WIN32_DATA:
   case STREAM_SPARSE_DATA:
   case STREAM_ENCRYPTED_FILE_DATA:
   case STREAM_ENCRYPTED_WIN32_DATA:
      break;
   default:
      retval = true;
      goto bail_out;
   }

   Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record DCR VolumeName=%s\n", dcr->VolumeName);

   /* Get dedup_volume */
   if(get_dedup_volume(p_ctx->dedup_volume_list, dcr->VolumeName, p_ctx->dedup_volume_group_prefix, dedup_volume)) {
      Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record Dedup VolumeName=%s\n", dedup_volume->volume_name);
   }
   else {
      Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not get dedup volume\n");
      Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not get dedup volume\n");
      goto bail_out;
   }
   
   /* If this is the first write */
   if(dedup_volume->first_write == true)
   {
      dedup_volume->first_write = false;
      
      /* Begin transaction for catalog_db */
      if(begin_transaction(dedup_volume->catalog_db)) {
         dedup_volume->catalog_db_transaction_in_progress = true;
         
         /* Delete previous backup attempt */
         if(cdb_delete_session(dedup_volume->catalog_db, rec->VolSessionId, rec->VolSessionTime))
         {
            /* Begin transaction foreach block_db */
            block_db = dedup_volume->block_db_list;
            while(block_db != NULL)
            {
               if((block_db->db_transaction_in_progress = begin_transaction(block_db->db)) == true && (block_db->digest_db_transaction_in_progress = begin_transaction(block_db->digest_db)) == true)
               {
                  block_db = block_db->next;
               }
               else
               {
                  Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not begin transaction for block_db Id=%d\n", block_db->id);
                  Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not begin transaction for block_db Id=%d\n", block_db->id);
                  goto bail_out;
               }
            }
            /* Load block_info_tree */
            if(load_block_info_tree(ctx, dedup_volume) == false)
            {
               Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not load block_info_tree\n");
               Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not load block_info_tree\n");
               goto bail_out;
            }
         }
         else {
            Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not delete previous session\n");
            Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not delete previous session\n");
            goto bail_out;
         }
      }
      else {
         Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not begin transaction for catalog_db\n");
         Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not begin transaction for catalog_db\n");
         goto bail_out;
      }
   }

   /* If write session id is not set, we add vol_session in catalog_db */
   if(dedup_volume->write_session.id == 0)
   {
      Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record add session VolSessionId=%d\n", rec->VolSessionId);
      Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record add session VolSessionTime=%d\n", rec->VolSessionTime);
      if(cdb_add_session(dedup_volume->catalog_db, rec->VolSessionId, rec->VolSessionTime, dedup_volume->write_session.id)) {
         Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record WriteSession Id=%d\n", dedup_volume->write_session.id);
      }
      else {
         Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not add session in catalog_db\n");
         Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not add session in catalog_db\n");
         goto bail_out;
      }
   }

   /* If write session id does not match manifest id, we close manifest file */
   if(dedup_volume->write_manifest.id != dedup_volume->write_session.id) {
      if(dedup_volume->write_manifest.file) {
         if(close_manifest_file(dedup_volume->write_manifest) == false) {
            Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not close manifest file Id=%d\n", dedup_volume->write_manifest.id);
            Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not close manifest file Id=%d\n", dedup_volume->write_manifest.id);
            goto bail_out;
         }
      }
      dedup_volume->write_manifest.id = dedup_volume->write_session.id;
   }

   /* If manifest file is not open, we open it */
   if(dedup_volume->write_manifest.file == NULL)
   {
      if(open_manifest_file(dedup_volume->path, dedup_volume->volume_name, dedup_volume->write_session.id, 'w', dedup_volume->write_manifest)) {
         Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record open manifest file Id=%d\n", dedup_volume->write_session.id);
      }
      else {
         Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not open manifest file Id=%d\n", dedup_volume->write_session.id);
         Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not open manifest file Id=%d\n", dedup_volume->write_session.id);
         goto bail_out;
      }
   }
   
   /*
    * Clone the data from the original DEV_RECORD to the converted one.
    * As we use the compression buffers for the data we need a new
    * DEV_RECORD without a new memory buffer so we call new_record here
    * with the with_data boolean set explicitly to false.
    */
   nrec = bfuncs->new_record(false);
   bfuncs->copy_record_state(nrec, rec);

   Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record FileIndex=%d\n", rec->FileIndex);
   Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record DataLen=%d\n", rec->data_len);
   
   /* If it is a new file, we add the file in the manifest */
   if(dedup_volume->write_session.file_index == 0 || dedup_volume->write_session.file_index != rec->FileIndex)
   {
      dedup_volume->write_session.file_index = rec->FileIndex;
      if(mf_add_file(dedup_volume->write_manifest, dedup_volume->write_session.file_index, rec->maskedStream)) {
         Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record add file to manifest FileId=%d\n", dedup_volume->write_session.file_index);
         /* We add record length */
         if(mf_add_record_len(dedup_volume->write_manifest, rec->data_len)) {
            Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record add record_len to manifest\n");
         }
         else {
            Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not add record_len to manisfest\n");
            Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not add record_len to manisfest\n");
            bfuncs->free_record(nrec);
            goto bail_out;
         }
      }
      else {
         Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not add file to manifest\n");
         Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not add file to manifest\n");
         bfuncs->free_record(nrec);
         goto bail_out;
      }
   }
   
   /* We dedup the record */
   if(dedup_record(ctx, dedup_volume, dedup_volume->write_manifest, rec) == false)
   {
      Jmsg(ctx, M_FATAL, "dedup-sd: write_dedup_record can not dedup record\n");
      Dmsg(ctx, dbglvl, "dedup-sd: write_dedup_record can not dedup record\n");
      bfuncs->free_record(nrec);
      goto bail_out;
   }

   nrec->data_len = 0;
   nrec->Stream = rec->Stream;
   nrec->maskedStream = rec->maskedStream;

   /*
    * If the input is just an intermediate value free it now.
    */
   if (intermediate_value) {
      bfuncs->free_record(dcr->after_rec);
   }
   dcr->after_rec = nrec;

   retval = true;

bail_out:
   return retval;
}

/*
 * Read the content of a read record and return the data as an alternative datastream.
 */
static bool read_dedup_record(bpContext *ctx, DCR *dcr)
{
   bool retval = false;
   bool result = false;

   /* Bareos Record */
   DEV_RECORD *rec, *nrec;
   bool intermediate_value = false;
   
   /* Dedup volume and volume informations */
   DEDUP_VOLUME *dedup_volume = NULL;
   
   struct plugin_ctx *p_ctx = (struct plugin_ctx *)ctx->pContext;

   /*
    * See what our starting point is. When dcr->after_rec is set we already have
    * a translated record by another SD plugin. Then we use that translated record
    * as the starting point otherwise we start at dcr->before_rec. When an earlier
    * translation already happened we can free that record when we have a success
    * full translation here as that record is of no use anymore.
    */
   if (dcr->after_rec) {
      rec = dcr->after_rec;
      intermediate_value = true;
   } else {
      rec = dcr->before_rec;
   }

   /*
    * We only do dedup for the following stream types:
    *
    * - STREAM_COMPRESSED_DATA
    * - STREAM_WIN32_COMPRESSED_DATA
    * - STREAM_SPARSE_COMPRESSED_DATA
    * - STREAM_ENCRYPTED_FILE_DATA
    * - STREAM_ENCRYPTED_WIN32_DATA
    */
   switch (rec->maskedStream) {
   case STREAM_FILE_DATA:
   case STREAM_WIN32_DATA:
   case STREAM_SPARSE_DATA:
   case STREAM_ENCRYPTED_FILE_DATA:
   case STREAM_ENCRYPTED_WIN32_DATA:
      break;
   default:
      retval = true;
      goto bail_out;
   }


   Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record DCR VolumeName=%s\n", dcr->VolumeName);

   /* Get dedup_volume */
   if(get_dedup_volume(p_ctx->dedup_volume_list, dcr->VolumeName, p_ctx->dedup_volume_group_prefix, dedup_volume)) {
      Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record Dedup VolumeName=%s\n", dedup_volume->volume_name);
   }
   else {
      Jmsg(ctx, M_FATAL, "dedup-sd: read_dedup_record can not get dedup volume\n");
      Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record can not get dedup volume\n");
      goto bail_out;
   }

   /* If read session id not set or VolSession change, we get the session id from the catalog_db */
   if(dedup_volume->read_session.id == 0 || dedup_volume->read_session.vol_session_id != rec->VolSessionId || dedup_volume->read_session.vol_session_time != rec->VolSessionTime)
   {
      dedup_volume->read_session.vol_session_id = rec->VolSessionId;
      dedup_volume->read_session.vol_session_time = rec->VolSessionTime;
      Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record ReadSession VolSessionId=%d\n", dedup_volume->read_session.vol_session_id);
      Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record ReadSession VolSessionTime=%d\n", dedup_volume->read_session.vol_session_time);
      result = cdb_get_session_id(dedup_volume->catalog_db, rec->VolSessionId, rec->VolSessionTime, dedup_volume->read_session.id);
      if(result == true && dedup_volume->read_session.id != -1) 
      {
         Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record ReadSession Id=%d\n", dedup_volume->read_session.id);
      }
      else
      {
         Jmsg(ctx, M_FATAL, "dedup-sd: read_dedup_record can not get session id\n");
         Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record can not get session id\n");
         goto bail_out;
      }
   }
   
   /* If write session id does not match manifest id, we close manifest file */
   if(dedup_volume->read_manifest.id != dedup_volume->read_session.id) {
      if(dedup_volume->read_manifest.file) {
         if(close_manifest_file(dedup_volume->read_manifest) == false) {
            Jmsg(ctx, M_FATAL, "dedup-sd: read_dedup_record can not close manifest file Id=%d\n", dedup_volume->read_manifest.id);
            Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record can not close manifest file Id=%d\n", dedup_volume->read_manifest.id);
            goto bail_out;
         }
      }
      dedup_volume->read_manifest.id = dedup_volume->read_session.id;
   }

   /* If manifest file is not open, we open it */
   if(dedup_volume->read_manifest.file == NULL)
   {
      if(open_manifest_file(dedup_volume->path, dedup_volume->volume_name, dedup_volume->read_session.id, 'r', dedup_volume->read_manifest)) {
         Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record open manifest file SessionId=%d\n", dedup_volume->read_session.id);
      }
      else {
         Jmsg(ctx, M_FATAL, "dedup-sd: read_dedup_record can not open manifest file\n");
         Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record can not open manifest file\n");
         goto bail_out;
      }
   }
   
   /*
    * Clone the data from the original DEV_RECORD to the converted one.
    * As we use the compression buffers for the data we need a new
    * DEV_RECORD without a new memory buffer so we call new_record here
    * with the with_data boolean set explicitly to false.
    */
   nrec = bfuncs->new_record(false);
   bfuncs->copy_record_state(nrec, rec);
   
   /* If it is a new file, we search the file in the manifest */
   if(dedup_volume->read_session.file_index == 0 || dedup_volume->read_session.file_index != rec->FileIndex)
   {
      dedup_volume->read_session.file_index = rec->FileIndex;
      result = mf_goto_file(dedup_volume->read_manifest, dedup_volume->read_session.file_index, rec->maskedStream);
      if(result == true) 
      {
         Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record mf_get_file fileIndex=%d stream=%d\n", dedup_volume->read_session.file_index, rec->maskedStream);
         result = mf_get_record_len(dedup_volume->read_manifest, dedup_volume->read_session.record_len);
         if(result == true) Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record RecordLen=%d\n", dedup_volume->read_session.record_len);
         else
         {
            Jmsg(ctx, M_FATAL, "dedup-sd: read_dedup_record can not get record len\n");
            Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record can not get record len\n");
            bfuncs->free_record(nrec);
            goto bail_out;
         }
      }
      else
      {
         Jmsg(ctx, M_FATAL, "dedup-sd: read_dedup_record can not get file fileIndex=%d stream=%d\n", dedup_volume->read_session.file_index, rec->maskedStream);
         Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record can not get file fileIndex=%d stream=%d\n", dedup_volume->read_session.file_index, rec->maskedStream);
         bfuncs->free_record(nrec);
         goto bail_out;
      }

   }

   nrec->data = get_memory(dedup_volume->read_session.record_len);
   nrec->data_len = 0;
   nrec->own_mempool = true;
   nrec->Stream = rec->maskedStream;
   nrec->maskedStream = rec->maskedStream;

   /* We load record from manifest and block_db */
   if(load_record(ctx, dedup_volume, nrec) == false)
   {
      Jmsg(ctx, M_FATAL, "dedup-sd: read_dedup_record can not load record\n");
      Dmsg(ctx, dbglvl, "dedup-sd: read_dedup_record can not load record\n");
      bfuncs->free_record(nrec);
      goto bail_out;
   }
  
   /*
    * If the input is just an intermediate value free it now.
    */
   if (intermediate_value) {
      bfuncs->free_record(dcr->after_rec);
   }
   dcr->after_rec = nrec;

   retval = true;

bail_out:
   return retval;
}

static bool open_catalog_db(char *dedup_volume_path, char *dedup_volume_name, sqlite3 *&db)
{
   int rc;
   int len;
   char *db_path;
   const char *sql;
   bool retval = false;
   bool add_trailing_slash = false;

   len = strlen(dedup_volume_path);
   if(len > 0 && dedup_volume_path[len-1] != '/') 
   {
      len += 1;
      add_trailing_slash = true;
   }   
   len += strlen(dedup_volume_name) + 5;
   
   db_path = (char *)malloc(len);
   strcpy(db_path, dedup_volume_path);
   if(add_trailing_slash) strcat(db_path, "/");
   strcat(db_path, dedup_volume_name);
   strcat(db_path, ".cdb");


   rc = sqlite3_open(db_path, &db);
   if(rc == SQLITE_OK)
   {
      sql = "PRAGMA page_size = 65536;" \
            "CREATE TABLE IF NOT EXISTS session(id INTEGER PRIMARY KEY, vol_session_id INTEGER, vol_session_time INTEGER, UNIQUE(vol_session_id, vol_session_time));" \
            "CREATE TABLE IF NOT EXISTS blockdb(id INTEGER PRIMARY KEY);" ;

     /* Execute SQL statement */
     rc = sqlite3_exec(db, sql, NULL, 0, NULL);
     if(rc == SQLITE_OK)
     {
         retval = true;
     }
   }
   
   free(db_path);
   db_path = NULL;

   return retval;
}

static bool open_block_db(char *dedup_volume_path, char *dedup_volume_name, sqlite3_int64 block_db_id, sqlite3 *&block_db)
{
   int rc;
   int len;
   char *db_path;
   const char *sql;
   bool retval = false;
   bool add_trailing_slash = false;
   char id[8];

   len = strlen(dedup_volume_path);
   if(len > 0 && dedup_volume_path[len-1] != '/') 
   {
      len += 1;
      add_trailing_slash = true;
   }   
   len += strlen(dedup_volume_name) + 13;
   
   db_path = (char *)malloc(len);
   strcpy(db_path, dedup_volume_path);
   if(add_trailing_slash) strcat(db_path, "/");
   strcat(db_path, dedup_volume_name);
   strcat(db_path, "-");
   sprintf(id, "%07lld", block_db_id);
   strcat(db_path, id);
   strcat(db_path, ".bdb");


   rc = sqlite3_open(db_path, &block_db);
   if(rc == SQLITE_OK)
   {
      sql = "PRAGMA page_size = 65536;" \
            "PRAGMA mmap_size = 268435456;" \
            "CREATE TABLE IF NOT EXISTS block(id INTEGER PRIMARY KEY, data BLOB);" ;
                         

     /* Execute SQL statement */
     rc = sqlite3_exec(block_db, sql, NULL, 0, NULL);
     if(rc == SQLITE_OK)
     {
         retval = true;
     }
   }
   
   free(db_path);
   db_path = NULL;

   return retval;
}

static bool open_digest_db(char *dedup_volume_path, char *dedup_volume_name, sqlite3_int64 digest_db_id, sqlite3 *&digest_db)
{
   int rc;
   int len;
   char *db_path;
   const char *sql;
   bool retval = false;
   bool add_trailing_slash = false;
   char id[8];

   len = strlen(dedup_volume_path);
   if(len > 0 && dedup_volume_path[len-1] != '/') 
   {
      len += 1;
      add_trailing_slash = true;
   }   
   len += strlen(dedup_volume_name) + 13;
   
   db_path = (char *)malloc(len);
   strcpy(db_path, dedup_volume_path);
   if(add_trailing_slash) strcat(db_path, "/");
   strcat(db_path, dedup_volume_name);
   strcat(db_path, "-");
   sprintf(id, "%07lld", digest_db_id);
   strcat(db_path, id);
   strcat(db_path, ".ddb");


   rc = sqlite3_open(db_path, &digest_db);
   if(rc == SQLITE_OK)
   {
      sql = "PRAGMA page_size = 65536;" \
            "CREATE TABLE IF NOT EXISTS block(id INTEGER PRIMARY KEY, digest BLOB);" ;
                         

     /* Execute SQL statement */
     rc = sqlite3_exec(digest_db, sql, NULL, 0, NULL);
     if(rc == SQLITE_OK)
     {
         retval = true;
     }
   }
   
   free(db_path);
   db_path = NULL;

   return retval;
}

static bool close_db(sqlite3 *&db)
{
   int rc;
   bool retval = true;

   if(db)
   {
      rc = sqlite3_close(db);
      if(rc != SQLITE_OK)
      {
         retval = false;
      }
   }
   
   return retval;
}

static bool begin_transaction(sqlite3 *&db)
{
   int rc;
   const char *sql;
   bool retval = false;

   sql = "BEGIN TRANSACTION;";
                         
   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, NULL, 0, NULL);
   if(rc == SQLITE_OK)
   {
       retval = true;
   }
   
   return retval;
}

static bool end_transaction(sqlite3 *&db)
{
   int rc;
   const char *sql;
   bool retval = false;

   sql = "END TRANSACTION;";
                         
   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, NULL, 0, NULL);
   if(rc == SQLITE_OK)
   {
       retval = true;
   }
   
   return retval;
}


static bool cdb_add_session(sqlite3 *&catalog_db, uint32_t volSessionId, uint32_t volSessionTime, sqlite3_int64 &session_id)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;

   if(catalog_db)
   {
      const char *sql = "INSERT INTO session(vol_session_id,vol_session_time) VALUES (:vol_session_id,:vol_session_time)";
      rc = sqlite3_prepare(catalog_db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Bind value */
         sqlite3_bind_int64(stmt, 1, volSessionId);
         sqlite3_bind_int64(stmt, 2, volSessionTime);

         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_DONE )
         {
            session_id = sqlite3_last_insert_rowid(catalog_db);
            retval = true;
         }
      }
   }
   
   return retval;
}

static bool cdb_get_session_id(sqlite3 *&catalog_db, uint32_t volSessionId, uint32_t volSessionTime, sqlite3_int64 &session_id)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;

   session_id = -1;

   if(catalog_db)
   {
      const char *sql = "SELECT id FROM session WHERE vol_session_id=:vol_session_id AND vol_session_time=:vol_session_time LIMIT 1";
      rc = sqlite3_prepare(catalog_db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Bind value */
         sqlite3_bind_int64(stmt, 1, volSessionId);
         sqlite3_bind_int64(stmt, 2, volSessionTime);

         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_ROW || rc == SQLITE_DONE )
         {
            if(rc == SQLITE_ROW) session_id = sqlite3_column_int64(stmt, 0);
            retval = true;
         }
         sqlite3_finalize(stmt);
      }
   }

   return retval;
}

static bool cdb_delete_session(sqlite3 *&catalog_db, uint32_t volSessionId, uint32_t volSessionTime)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;

   if(catalog_db)
   {
      const char *sql = "DELETE FROM session WHERE vol_session_id=:vol_session_id AND vol_session_time=:vol_session_time";
      rc = sqlite3_prepare(catalog_db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Bind value */
         sqlite3_bind_int64(stmt, 1, volSessionId);
         sqlite3_bind_int64(stmt, 2, volSessionTime);

         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_DONE )
         {
            retval = true;
         }
      }
   }
   
   return retval;
}

static bool cdb_add_block_db(sqlite3 *&catalog_db, sqlite3_int64 &block_db_id)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;

   if(catalog_db)
   {
      const char *sql = "INSERT INTO blockdb(id) VALUES (null)";
      rc = sqlite3_prepare(catalog_db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_DONE )
         {
            block_db_id = sqlite3_last_insert_rowid(catalog_db);
            retval = true;
         }
         sqlite3_finalize(stmt);
      }
   }
   
   return retval;
}

static bool cdb_block_db_exist(sqlite3 *&catalog_db, sqlite3_int64 block_db_id, bool &exist)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;
   
   exist = false;

   if(catalog_db)
   {
      const char *sql = "SELECT id FROM blockdb WHERE id=:id LIMIT 1";
      rc = sqlite3_prepare(catalog_db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Bind value */
         sqlite3_bind_int64(stmt, 1, block_db_id);
         
         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_ROW || rc == SQLITE_DONE )
         {
            if(rc == SQLITE_ROW) exist = true;
            retval = true;

         }
         sqlite3_finalize(stmt);
      }
   }

   return retval;
}


static bool bdb_add_block(sqlite3 *&block_db, char *block, uint32_t block_len, sqlite3_int64 &block_id)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;
   
   block_id = -1;

   if(block_db)
   {
      const char *sql = "INSERT INTO block(data) VALUES (:data)";
      rc = sqlite3_prepare(block_db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Bind value */
         sqlite3_bind_blob(stmt, 1, block, block_len, 0);

         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_DONE )
         {
            block_id = sqlite3_last_insert_rowid(block_db);
            retval = true;
         }
         sqlite3_finalize(stmt);
      }
   }

   return retval;
}

static bool bdb_get_block(sqlite3 *&db, sqlite3_int64 block_id, char *&block, sqlite3_int64 &block_len)
{
   int rc;
   int len = 0;
   bool retval = false;
   sqlite3_stmt *stmt;
   
   block = NULL;
   block_len = -1;

   if(db)
   {
      const char *sql = "SELECT data FROM block WHERE id=:id LIMIT 1";
      rc = sqlite3_prepare(db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Bind value */
         sqlite3_bind_int64(stmt, 1, block_id);
         
         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_ROW || rc == SQLITE_DONE )
         {
            if(rc == SQLITE_ROW)
            {
               len = sqlite3_column_bytes(stmt, 0);
			   block = (char *)malloc(len);			
			   memcpy(block, sqlite3_column_blob(stmt, 0), len);
               block_len = len;
            }
            retval = true;

         }
         sqlite3_finalize(stmt);
      }
   }

   return retval;
}

static bool bdb_get_page_count(sqlite3 *&db, sqlite3_int64 &page_count)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;
   
   page_count = -1;

   if(db)
   {
      const char *sql = "PRAGMA page_count";
      rc = sqlite3_prepare(db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_ROW || rc == SQLITE_DONE )
         {
            if(rc == SQLITE_ROW)
            {
               page_count = sqlite3_column_int64(stmt, 0);
            }
            retval = true;

         }
         sqlite3_finalize(stmt);
      }
   }

   return retval;
}


static bool ddb_add_digest(sqlite3 *&digest_db, sqlite3_int64 block_id, unsigned char *digest)
{
   int rc;
   bool retval = false;
   sqlite3_stmt *stmt;

   if(digest_db)
   {
      const char *sql = "INSERT INTO block(id,digest) VALUES (:id,:digest)";
      rc = sqlite3_prepare(digest_db, sql, strlen(sql), &stmt, NULL);
      if( rc == SQLITE_OK )
      {
         /* Bind value */
         sqlite3_bind_int64(stmt, 1, block_id);
         sqlite3_bind_blob(stmt, 2, digest, 32, 0);

         /* Evaluate SQL statement */
         rc = sqlite3_step(stmt);
         if( rc == SQLITE_DONE )
         {
            retval = true;
         }
         sqlite3_finalize(stmt);
      }
   }
   
   return retval;         
}

static bool add_block(bpContext *ctx, DEDUP_VOLUME *dedup_volume, char *block, uint32_t block_len, unsigned char *digest, sqlite3_int64 &block_db_id, sqlite3_int64 &block_id)
{
   bool retval = false;
   BLOCK_DB *block_db = NULL;
   BLOCK_DB *previous_block_db = NULL;
   
   block_db = dedup_volume->block_db_list;

   block_db_id = -1;
   block_id = -1;   

   if(dedup_volume->catalog_db)
   {
      /* Select block_db to use */
      while(block_db != NULL)
      {
         if(block_db->db)
         {
            if(block_db->size < MAX_BLOCK_DB_SIZE) break;
         }
         else
         {
            Dmsg(ctx, dbglvl, "dedup-sd: add_block db of block_db is not available\n");
            goto bail_out;
         }
         previous_block_db = block_db;
         block_db = block_db->next;
      }

      /* If there is no free block_db, a new one is created */
	  if(block_db == NULL)
      {
         /* Create a new block_db in the catalog_db */
         if(cdb_add_block_db(dedup_volume->catalog_db, block_db_id))
         {
            /* Create new block_db */
            block_db = (BLOCK_DB *)malloc(sizeof(BLOCK_DB));
            block_db->id = block_db_id;
            block_db->db = NULL;
            block_db->digest_db = NULL;
            block_db->size = 0;
            block_db->db_transaction_in_progress = false;
            block_db->digest_db_transaction_in_progress = false;
            block_db->next = NULL;

            /* Add the new block_db in the block_db_list */
            if(dedup_volume->block_db_list == NULL) dedup_volume->block_db_list = block_db;
            else previous_block_db->next = block_db;

            /* Open the new block_db */
            if(open_block_db(dedup_volume->path, dedup_volume->volume_name, block_db->id, block_db->db))
            {
               /* Begin transaction */
               if(begin_transaction(block_db->db) == true)
               {
                  block_db->db_transaction_in_progress = true;
                  /* Open the new digest_db */
                  if(open_digest_db(dedup_volume->path, dedup_volume->volume_name, block_db->id, block_db->digest_db))
                  {
                     if(begin_transaction(block_db->digest_db) == true)
                     {
                        block_db->digest_db_transaction_in_progress = true;
                     }
                     else
                     {
                        Dmsg(ctx, dbglvl, "dedup-sd: add_block can not begin transaction for the new digest_db Id=%d\n", block_db->id); 
                        goto bail_out;
                     }
                  }
                  else
                  {
                     Dmsg(ctx, dbglvl, "dedup-sd: add_block can not open the new digest_db Id=%d\n", block_db->id); 
                     goto bail_out;
                  }
               }
               else
               {
                  Dmsg(ctx, dbglvl, "dedup-sd: add_block can not begin transaction for the new block_db Id=%d\n", block_db->id); 
                  goto bail_out;
               }
            }
            else 
            {
               Dmsg(ctx, dbglvl, "dedup-sd: add_block can not open the new block_db Id=%d\n", block_db->id); 
               goto bail_out;
            }
         }
         else 
         {
            Dmsg(ctx, dbglvl, "dedup-sd: add_block can not add new block_db in catalog_db\n");
            goto bail_out;
         }
      }

      /* If we have a block_db, we add the block */
      if(block_db != NULL && block_db->db != NULL)
      {
         if( bdb_add_block(block_db->db, block, block_len, block_id) == true)
         {
            block_db_id = block_db->id;
            block_db->size += block_len;
                        
            if(ddb_add_digest(block_db->digest_db, block_id, digest) == true)
            {
               retval = true;
               
               /* If the size of block_db is greater than the max_block_db_size, we commit the transaction */
               if(block_db->size >= MAX_BLOCK_DB_SIZE)
               {
                  if(end_transaction(block_db->db) == true) 
                  {
                     block_db->db_transaction_in_progress = false; 
                     if(end_transaction(block_db->digest_db) == true) 
                     {
                        block_db->digest_db_transaction_in_progress = false;
                        if(begin_transaction(block_db->db) == true) 
                        {
                           block_db->db_transaction_in_progress = true; 
                           if(begin_transaction(block_db->digest_db) == true) block_db->digest_db_transaction_in_progress = true;
                           else
                           {
                              Dmsg(ctx, dbglvl, "dedup-sd: add_block can not begin transaction for digest_db Id=%d\n", block_db->id);
                              retval = false;
                           } 
                        }
                        else
                        {
                           Dmsg(ctx, dbglvl, "dedup-sd: add_block can not begin transaction for block_db Id=%d\n", block_db->id);
                           retval = false;
                        }
                     }
                     else
                     {
                        Dmsg(ctx, dbglvl, "dedup-sd: add_block can not commit the transaction for digest_db Id=%d\n", block_db->id);
                        retval = false;
                     }
                  }
                  else
                  {
                     Dmsg(ctx, dbglvl, "dedup-sd: add_block can not commit the transaction for block_db Id=%d\n", block_db->id);
                     retval = false;
                  }
               }
            }
            else Dmsg(ctx, dbglvl, "dedup-sd: add_block can not add digest to the digest_db Id=%d\n", block_db->id); 
         }
         else Dmsg(ctx, dbglvl, "dedup-sd: add_block can not add block to the block_db Id=%d\n", block_db->id); 
      }
   }
   else Dmsg(ctx, dbglvl, "dedup-sd: add_block catalog_db is not available\n");

bail_out:
   return retval;
}

static bool check_dedup_volume_name(char *volume_name, char *dedup_volume_prefix)
{
   bool retval = false;
   char *token;
   char *tmp_dedup_volume_prefix = NULL;

   if(dedup_volume_prefix)
   {
      tmp_dedup_volume_prefix = (char *)malloc(strlen(dedup_volume_prefix) + 1);
      strcpy(tmp_dedup_volume_prefix, dedup_volume_prefix);
   }

   /* Get the first token */
   token = strtok(tmp_dedup_volume_prefix, PREFIX_SEPARATOR);
   
   /* Walk through other tokens */
   while( token != NULL ) 
   {
      if(strncmp(volume_name, token, strlen(token)) == 0) 
      {
         retval = true;
         break;
      }
      token = strtok(NULL, PREFIX_SEPARATOR);
   }

   if(tmp_dedup_volume_prefix) {
      free(tmp_dedup_volume_prefix);
      tmp_dedup_volume_prefix = NULL;
   }

   return retval;
}

static bool add_dedup_volume(DEDUP_VOLUME *&dedup_volume_list, char *volume_name, char *dedup_volume_path, char *dedup_volume_group_prefix, DEDUP_VOLUME *&dedup_volume)
{
   bool retval = true; //TODO
   int len = 0;
   char *token;
   char *dedup_volume_name = NULL;
   char *tmp_dedup_volume_group_prefix = NULL;
   bool add_trailing_slash = false;
   DEDUP_VOLUME *previous_dedup_volume = NULL;

   if(dedup_volume_group_prefix) {
      tmp_dedup_volume_group_prefix = (char *)malloc(strlen(dedup_volume_group_prefix) + 1);
      strcpy(tmp_dedup_volume_group_prefix, dedup_volume_group_prefix);
   }

   /* Get the first token */
   token = strtok(tmp_dedup_volume_group_prefix, PREFIX_SEPARATOR);
   
   /* Walk through other tokens */
   while( token != NULL ) 
   {
      if(strncmp(volume_name, token, strlen(token)) == 0) 
      {
         dedup_volume_name = (char *)malloc(strlen(volume_name) - strlen(token) + 1);
         strcpy(dedup_volume_name, &volume_name[strlen(token)]);
         break;
      }
      token = strtok(NULL, PREFIX_SEPARATOR);
   }

   if(dedup_volume_name == NULL) 
   {
      dedup_volume_name = (char *)malloc(strlen(volume_name) + 1);
      strcpy(dedup_volume_name, volume_name);
   }

   
   /* We check if the dedup volume is already in the list */
   dedup_volume = dedup_volume_list;
   while(dedup_volume != NULL) {
      if(strcmp(dedup_volume->volume_name, dedup_volume_name) == 0) {
         break;
      }
      previous_dedup_volume = dedup_volume;
      dedup_volume = dedup_volume->next;
   }

   /* If dedup_volume not present in the list, we add a new dedup_volume */
   if(dedup_volume == NULL) {
      dedup_volume = (DEDUP_VOLUME *)malloc(sizeof(DEDUP_VOLUME));
      dedup_volume->volume_name = (char *)malloc(strlen(dedup_volume_name) + 1);
      strcpy(dedup_volume->volume_name, dedup_volume_name);
      dedup_volume->read_session.vol_session_id = 0;
      dedup_volume->read_session.vol_session_time = 0;
      dedup_volume->read_session.id = 0;
      dedup_volume->read_session.file_index = 0;
      dedup_volume->read_session.record_len = 0;
      dedup_volume->write_session.vol_session_id = 0;
      dedup_volume->write_session.vol_session_time = 0;
      dedup_volume->write_session.id = 0;
      dedup_volume->write_session.file_index = 0;
      dedup_volume->write_session.record_len = 0;
      dedup_volume->block_db_list = NULL;
      dedup_volume->block_info_tree = NULL;
      dedup_volume->read_manifest.id = 0;
      dedup_volume->read_manifest.file = NULL;
      dedup_volume->read_manifest.last_line[0] = '\n';
      dedup_volume->write_manifest.id = 0;
      dedup_volume->write_manifest.file = NULL;
      dedup_volume->write_manifest.last_line[0] = '\n';
      dedup_volume->first_read = true;
      dedup_volume->first_write = true;
      dedup_volume->catalog_db = NULL;
      dedup_volume->catalog_db_transaction_in_progress = false;
      dedup_volume->next = NULL;

      len = strlen(dedup_volume_path);
      if(len > 0 && dedup_volume_path[len-1] != '/') 
      {
         len += 1;
         add_trailing_slash = true;
      }   
      len += strlen(dedup_volume_name) + 2;

      dedup_volume->path = (char *)malloc(len);      
      strcpy(dedup_volume->path, dedup_volume_path);
      if(add_trailing_slash) strcat(dedup_volume->path, "/");
      strcat(dedup_volume->path, dedup_volume_name);
      strcat(dedup_volume->path, "/");
   
      if(dedup_volume_list == NULL) {
         dedup_volume_list = dedup_volume;
      }
      else {
         previous_dedup_volume->next = dedup_volume;
      }
   }

   if(dedup_volume_name) {
      free(dedup_volume_name);
      dedup_volume_name = NULL;
   }

   if(tmp_dedup_volume_group_prefix) {
      free(tmp_dedup_volume_group_prefix);
      tmp_dedup_volume_group_prefix = NULL;
   }

   return retval;
}

static bool get_dedup_volume(DEDUP_VOLUME *dedup_volume_list, char *volume_name, char *dedup_volume_group_prefix, DEDUP_VOLUME *&dedup_volume)
{
   bool retval = false;
   char *token;
   char *dedup_volume_name = NULL;
   char *tmp_dedup_volume_group_prefix = NULL;

   if(dedup_volume_group_prefix) {
      tmp_dedup_volume_group_prefix = (char *)malloc(strlen(dedup_volume_group_prefix) + 1);
      strcpy(tmp_dedup_volume_group_prefix, dedup_volume_group_prefix);
   }

   /* Get the first token */
   token = strtok(tmp_dedup_volume_group_prefix, PREFIX_SEPARATOR);
   
   /* Walk through other tokens */
   while( token != NULL ) 
   {
      if(strncmp(volume_name, token, strlen(token)) == 0) 
      {
         dedup_volume_name = (char *)malloc(strlen(volume_name) - strlen(token) + 1);
         strcpy(dedup_volume_name, &volume_name[strlen(token)]);
         break;
      }
      token = strtok(NULL, PREFIX_SEPARATOR);
   }

   if(dedup_volume_name == NULL) 
   {
      dedup_volume_name = (char *)malloc(strlen(volume_name) + 1);
      strcpy(dedup_volume_name, volume_name);
   }

   dedup_volume = dedup_volume_list;
   while(dedup_volume != NULL) {
      if(strcmp(dedup_volume->volume_name, dedup_volume_name) == 0) {
         retval = true;
         break;
      }
      dedup_volume = dedup_volume->next;
   }

   if(dedup_volume_name) {
      free(dedup_volume_name);
      dedup_volume_name = NULL;
   }

   if(tmp_dedup_volume_group_prefix) {
      free(tmp_dedup_volume_group_prefix);
      tmp_dedup_volume_group_prefix = NULL;
   }

   return retval;
}

static bool free_dedup_volume(bpContext *ctx, DEDUP_VOLUME *&dedup_volume)
{
   bool retval = true;

   if(dedup_volume)
   {
      retval = free_dedup_volume(ctx, dedup_volume->next);
      
      if(free_block_db(dedup_volume->block_db_list) == false) retval = false;
      if(dedup_volume->catalog_db_transaction_in_progress == true) if(end_transaction(dedup_volume->catalog_db) == false) retval = false;
      free_block_info(dedup_volume->block_info_tree);
      dedup_volume->read_manifest.id = 0;
      if(dedup_volume->read_manifest.file) if(close_manifest_file(dedup_volume->read_manifest) == false) retval = false;
      dedup_volume->read_manifest.last_line[0] = '\n';
      dedup_volume->write_manifest.id = 0;
      if(dedup_volume->write_manifest.file) if(close_manifest_file(dedup_volume->write_manifest) == false) retval = false;
      dedup_volume->write_manifest.last_line[0] = '\n';
      if(dedup_volume->catalog_db) if(close_db(dedup_volume->catalog_db) == false) retval = false;
      free(dedup_volume->path);
      dedup_volume->path = NULL;
      free(dedup_volume->volume_name);
      dedup_volume->volume_name = NULL;
      free(dedup_volume);
      dedup_volume = NULL;
   }

   return retval;
}

static bool get_block_info(BLOCK_INFO *block_info_tree, unsigned char *digest, BLOCK_INFO **&block_info)
{
   bool retval = false;
   int result = 0;
   
   block_info = &block_info_tree;
   
   while((*block_info) != NULL)
   {
      result = memcmp((const char*)digest, (const char*)(*block_info)->digest, 32);
   
      if(result < 0)
      {
         block_info = &((*block_info)->left);
         if(*block_info == NULL) break;
      }
      else if(result > 0) 
      {
         block_info = &((*block_info)->right);
         if(*block_info == NULL) break;
      }
      else if(result == 0)
      {
         retval = true;
         break;
      }
   }
   return retval;
}


static bool free_block_info(BLOCK_INFO *&block_info)
{
   if(block_info)
   {
      free_block_info(block_info->left);
      free_block_info(block_info->right);
      free(block_info);
      block_info = NULL;
   }

   return true;
}

static bool load_block_db_list(bpContext *ctx, DEDUP_VOLUME *&dedup_volume)
{
   bool retval = true;
   sqlite3_int64 block_db_id = 1;
   bool exist = false;
   BLOCK_DB *block_db = NULL;
   BLOCK_DB *current_block_db = NULL;
   
   /* Foreach block_db */
   while(block_db_id <= MAX_BLOCK_DB && (cdb_block_db_exist(dedup_volume->catalog_db, block_db_id, exist) == true) && exist == true)
   { 
      block_db = (BLOCK_DB *)malloc(sizeof(BLOCK_DB));
      block_db->id = block_db_id;
      block_db->db = NULL;
      block_db->digest_db = NULL;
      block_db->size = 0;
      block_db->db_transaction_in_progress = false;
      block_db->digest_db_transaction_in_progress = false;
      block_db->next = NULL;

      /* Open block_db */
      if(open_block_db(dedup_volume->path, dedup_volume->volume_name, block_db->id, block_db->db) == false) 
      {
         Dmsg(ctx, dbglvl, "dedup-sd: load_block_db_list can not open block database id=%d\n", block_db->id);
         free(block_db);
         block_db = NULL;
         retval = false;
         break;
      }
      else 
      { 
         /* Open digest_db */
         Dmsg(ctx, dbglvl, "dedup-sd: load_block_db_list open block database id=%d\n", block_db->id); 
         bdb_get_page_count(block_db->db, block_db->size);
         Dmsg(ctx, dbglvl, "dedup-sd: load_block_db_list page_count=%d\n", block_db->size);
         block_db->size = block_db->size * 65536;
         if(open_digest_db(dedup_volume->path, dedup_volume->volume_name, block_db->id, block_db->digest_db) == false)
         {
            Dmsg(ctx, dbglvl, "dedup-sd: load_block_db_list can not open digest database id=%d\n", block_db->id);
            close_db(block_db->db);
            free(block_db);
            block_db = NULL;
            retval = false;
            break;
         }
      }

      if(dedup_volume->block_db_list == NULL) {
         dedup_volume->block_db_list = block_db;
      }
      else {
         current_block_db->next = block_db;
      }

      current_block_db = block_db;
      block_db_id++;
   }

   return retval;
}

static bool free_block_db(BLOCK_DB *&block_db)
{
   bool retval = true;
   if(block_db)
   {
      retval = free_block_db(block_db->next);
      if(block_db->db_transaction_in_progress == true) if(end_transaction(block_db->db) == false) retval = false;
      if(block_db->digest_db_transaction_in_progress == true) if(end_transaction(block_db->digest_db) == false) retval = false;
      if(block_db->db) close_db(block_db->db);
      if(block_db->digest_db) close_db(block_db->digest_db);
      free(block_db);
      block_db = NULL;
   }

   return retval;
}

static bool open_manifest_file(char *dedup_volume_path, char *dedup_volume_name, sqlite3_int64 session_id, char mode, MANIFEST_FILE &manifest)
{
   int len;
   char id[8];
   char *file_path;
   bool retval = false;
   bool add_trailing_slash = false;

   manifest.file = NULL;
   manifest.last_line[0] = '\n';

   if(mode == 'r' || mode == 'w')
   {
      len = strlen(dedup_volume_path);
      if(len > 0 && dedup_volume_path[len-1] != '/') 
      {
         len += 1;
         add_trailing_slash = true;
      }   
      len += strlen(dedup_volume_name) + 13;
   
      file_path = (char *)malloc(len);
      strcpy(file_path, dedup_volume_path);
      if(add_trailing_slash) strcat(file_path, "/");
      strcat(file_path, dedup_volume_name);
      strcat(file_path, "-");
      sprintf(id, "%07lld", session_id);
      strcat(file_path, id);
      strcat(file_path, ".maf");

      manifest.file = fopen(file_path, (const char*)&mode);
      if(manifest.file)
      {
         retval = true;
      }

      free(file_path);
      file_path = NULL;
   }

   return retval;

}

static bool close_manifest_file(MANIFEST_FILE &manifest)
{
   bool retval = false;

   if(manifest.file == NULL)
   {
      retval = true;
   }
   else
   {
      if(fclose(manifest.file) == 0)
      {
         retval = true;
      }
   }

   if(retval)
   {
      manifest.id = 0;
      manifest.file = NULL;
      manifest.last_line[0] = '\n';
   }

   return retval;
}

static bool mf_add_file(MANIFEST_FILE &manifest, int32_t fileIndex, int32_t stream)
{
   bool retval = false;
   char line[MAX_MANIFEST_LINE_LENGTH];

   if(sprintf(line, "F%" PRId32 "S%" PRId32 "\n", fileIndex, stream) >= 0)
   {
      if(fwrite(line,1, strlen(line), manifest.file) == strlen(line))
      {
         retval = true;
      }
   }

   return retval;
}

static bool mf_add_record_len(MANIFEST_FILE &manifest, uint32_t record_len)
{
   bool retval = false;
   char line[MAX_MANIFEST_LINE_LENGTH];

   if(sprintf(line, "R%" PRIu32 "\n", record_len) >= 0)
   {
      if(fwrite(line,1, strlen(line), manifest.file) == strlen(line))
      {
         retval = true;
      }
   }

   return retval;
}

static bool mf_add_block(MANIFEST_FILE &manifest, sqlite3_int64 block_db_id, sqlite3_int64 block_id)
{
   bool retval = false;
   char line[MAX_MANIFEST_LINE_LENGTH];

   if(sprintf(line, "D%lldB%lld\n", block_db_id, block_id) >= 0)
   {
      if(fwrite(line,1, strlen(line), manifest.file) == strlen(line))
      {
         retval = true;
      }
   }

   return retval;
}

static bool mf_goto_file(MANIFEST_FILE &manifest, int32_t fileIndex, int32_t stream)
{
   bool retval = false;
   int32_t last_fileIndex = 0;
   int32_t last_stream = 0;
   

   while(retval == false)
   {
      if(manifest.last_line[0] == '\n' && fgets(manifest.last_line,MAX_MANIFEST_LINE_LENGTH, (FILE*)manifest.file) == NULL) break;
      else
      {
         if(manifest.last_line[0] == 'F')
         {
            if(sscanf(manifest.last_line, "F%" SCNd32 "S%" SCNd32 "\n", &last_fileIndex, &last_stream) == 2)
            {
               manifest.last_line[0] = '\n';
               if(last_fileIndex == fileIndex && last_stream == stream) retval = true;
            }
            else 
            {
               //TODO Need to clear the line ?
               manifest.last_line[0] = '\n';
               break;
            }
         }
         else manifest.last_line[0] = '\n';
      }
   }

   return retval;
}

static bool mf_get_record_len(MANIFEST_FILE &manifest, uint32_t &record_len)
{
   bool retval = false;

   record_len = 0;
   
   if(manifest.last_line[0] == '\n')
   {
      if(fgets(manifest.last_line,MAX_MANIFEST_LINE_LENGTH, (FILE*)manifest.file) != NULL)
      {
         if(manifest.last_line[0] == 'R') 
         {
            if(sscanf(manifest.last_line, "R%" SCNu32 "\n", &record_len) == 1)
            {
             manifest.last_line[0] = '\n';
             retval = true;
            }
         }
      }
   }

   return retval;
}

static bool mf_get_block(MANIFEST_FILE &manifest, sqlite3_int64 &block_db_id, sqlite3_int64 &block_id)
{
   bool retval = false;

   block_db_id = -1;
   block_id = -1;
      
   if(manifest.last_line[0] == '\n')
   {
      if(fgets(manifest.last_line,MAX_MANIFEST_LINE_LENGTH, (FILE*)manifest.file) != NULL)
      {
         if(manifest.last_line[0] == 'D')
         {
            if(sscanf(manifest.last_line, "D%lldB%lld\n", &block_db_id, &block_id) == 2)
            {
               manifest.last_line[0] = '\n';
               retval = true;
            }
         }
      }
   }

   return retval;
}

static mode_t get_umask()
{
    mode_t mask = umask(0);
    umask (mask);
    return mask;
}

static bool create_directory(char *path)
{
   struct stat sb;
   bool retval = false;

   /*
    * If the directory exists, we're done.  We do not further check
    * the type of the file, DB will fail appropriately if it's the
    * wrong type.
    */
   if (stat(path, &sb) == 0) retval = true;
   else
   {
      /* Create the directory, read/write/access owner only. */
      //if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == 0) retval = true;
      /* Create the directory. */
      mode_t mask = get_umask();
      if (mkdir(path, 0777 & ~mask) == 0) retval = true;
   }

   return retval;
}

static bool dedup_record(bpContext *ctx, DEDUP_VOLUME *&dedup_volume, MANIFEST_FILE &manifest, DEV_RECORD *rec)
{
   bool retval = true;

   /* Blake2b */
   blake2b_state S[1];
   unsigned char digest[32] = {0};
   
   /* Block */
   sqlite3_int64 block_db_id = 0;
   sqlite3_int64 block_id = 0;
   uint32_t block_start = 0;

   /* Fixed block deduplication */
   uint32_t chunk_size = FIXED_BLOCK_SIZE;

   /* Variable block deduplication */
   struct rabin_polynomial *head = NULL;
   struct rabin_polynomial *cur_poly = NULL;
   struct rab_block_info *block = NULL;

   /* Block information */
   struct BLOCK_INFO **block_info = NULL;
   struct BLOCK_INFO *new_block_info = NULL;

   struct plugin_ctx *p_ctx = (struct plugin_ctx *)ctx->pContext;

   /* Use variable block size deduplication */
   if(p_ctx->variable_block_dedup)
   {
      initialize_rabin_polynomial(3 , MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, AVG_BLOCK_SIZE);
      Dmsg(ctx, dbglvl, "dedup-sd: dedup_record initialize_rabin_polynomial\n");
      block=read_rabin_block(rec->data, rec->data_len, block);
      Dmsg(ctx, dbglvl, "dedup-sd: dedup_record read_rabin_block\n");
      head=block->head;
   
      cur_poly = head;
      while(cur_poly != NULL) {
         
         Dmsg(ctx, dbglvl, "dedup-sd: dedup_record block_length=%d\n", cur_poly->length);

         blake2b_init(S, 32);
         blake2b_update(S, (const u_int8_t*)&(rec->data[block_start]), cur_poly->length);
         blake2b_final(S, digest, 32);
         
         if(get_block_info(dedup_volume->block_info_tree, digest, block_info))
         {
            if(mf_add_block(manifest, (*block_info)->block_db_id, (*block_info)->block_id) == false)
            {
               Dmsg(ctx, dbglvl, "dedup-sd: dedup_record can not add block to manifest file\n");
               retval = false;
               break;
            }
         }
         else
         {
            if(add_block(ctx, dedup_volume, (char *)&(rec->data[block_start]), cur_poly->length, digest, block_db_id, block_id))
            {
               if(mf_add_block(manifest, block_db_id, block_id))
               {
                  new_block_info = (BLOCK_INFO *)malloc(sizeof(BLOCK_INFO));
                  new_block_info->block_db_id = block_db_id;
                  new_block_info->block_id = block_id;
                  memcpy(&(new_block_info->digest[0]), &digest[0], 32);
                  new_block_info->left = NULL;
                  new_block_info->right = NULL;
                  if(dedup_volume->block_info_tree == NULL) dedup_volume->block_info_tree = new_block_info;
                  else (*block_info) = new_block_info;
               }
               else
               {
                  Dmsg(ctx, dbglvl, "dedup-sd: dedup_record can not add block to manifest file\n");
                  retval = false;
                  break;
               }
            }
            else
            {
               Dmsg(ctx, dbglvl, "dedup-sd: dedup_record can not add block to block_db\n");
               retval = false;
               break;
            }
         }
         
         block_start += cur_poly->length;
         cur_poly=cur_poly->next_polynomial;
      }

      free_rabin_fingerprint_list(head);
   }
   /* Use fixed block size deduplication */
   else
   {
      while(block_start < rec->data_len) {
         if(block_start + chunk_size > rec->data_len)
         {
            chunk_size = rec->data_len - block_start;
         }

         Dmsg(ctx, dbglvl, "dedup-sd: dedup_record block_length=%d\n", chunk_size);

         blake2b_init(S, 32);
         blake2b_update(S, (const u_int8_t*)&(rec->data[block_start]), chunk_size);
         blake2b_final(S, digest, 32);
         
         if(get_block_info(dedup_volume->block_info_tree, digest, block_info))
         {
            if(mf_add_block(manifest, (*block_info)->block_db_id, (*block_info)->block_id) == false)
            {
               Dmsg(ctx, dbglvl, "dedup-sd: dedup_record can not add block to manifest file\n");
               retval = false;
               break;
            }
         }
         else
         {
            if(add_block(ctx, dedup_volume, (char *)&(rec->data[block_start]), chunk_size, digest, block_db_id, block_id))
            {
               if(mf_add_block(manifest, block_db_id, block_id))
               {
                  new_block_info = (BLOCK_INFO *)malloc(sizeof(BLOCK_INFO));
                  new_block_info->block_db_id = block_db_id;
                  new_block_info->block_id = block_id;
                  memcpy(&(new_block_info->digest[0]), &digest[0], 32);
                  new_block_info->left = NULL;
                  new_block_info->right = NULL;
                  if(dedup_volume->block_info_tree == NULL) dedup_volume->block_info_tree = new_block_info;
                  else (*block_info) = new_block_info;
               }
               else
               {
                  Dmsg(ctx, dbglvl, "dedup-sd: dedup_record can not add block to manifest file\n");
                  retval = false;
                  break;
               }
            }
            else
            {
               Dmsg(ctx, dbglvl, "dedup-sd: dedup_record can not add block to block_db\n");
               retval = false;
               break;
            }
         }
         
         block_start += chunk_size;
      }
   }
   
   return retval;
}

static bool load_record(bpContext *ctx, DEDUP_VOLUME *&dedup_volume, DEV_RECORD *rec)
{
   bool retval = true;
   bool result;

   /* Block */
   BLOCK_DB *block_db;
   sqlite3_int64 block_db_id = 0;
   sqlite3_int64 block_id = 0;
   uint32_t block_start = 0;
   char *block = NULL;
   sqlite3_int64 block_len = 0;
   
   /* We get block from manifest until record is full or we reached the end of file */
   while(block_start < dedup_volume->read_session.record_len && (result = mf_get_block(dedup_volume->read_manifest, block_db_id, block_id)) == true && block_db_id != -1 && block_id != -1)
   {
      Dmsg(ctx, dbglvl, "dedup-sd: load_record mf_get_block block_db_id=%d block_id=%d\n", block_db_id, block_id);
      block_db = dedup_volume->block_db_list;
      while(block_db != NULL && block_db->id != block_db_id)
      {
         block_db = block_db->next;
      }
      
      if(block_db != NULL)
      {
         result = bdb_get_block(block_db->db, block_id, block, block_len);
         if(result == true && block_len != -1)
         {
            Dmsg(ctx, dbglvl, "dedup-sd: load_record block_len=%d\n", block_len);
            memcpy(&(rec->data[block_start]), block, block_len);
            free(block);
            block = NULL;
            block_start += block_len;
            rec->data_len += block_len;
         }
         else
         {
            Jmsg(ctx, M_FATAL, "dedup-sd: load_record can not get block\n");
            Dmsg(ctx, dbglvl, "dedup-sd: load_record can not get block\n");
            if(block)
            {
               free(block);
               block = NULL;
            }
            retval = false;
            break;
         }
      }
      else
      {
         Jmsg(ctx, M_FATAL, "dedup-sd: load_record can not get block_db\n");
         Dmsg(ctx, dbglvl, "dedup-sd: load_record can not get block_db\n");
         if(block)
         {
            free(block);
            block = NULL;
         }
         retval = false;
         break;
      }
   }
     
   return retval;
}

/* Load all block_info in a binary tree stored in memory */
static bool load_block_info_tree(bpContext *ctx, DEDUP_VOLUME *&dedup_volume)
{
   int rc;
   bool retval = true;
   
   sqlite3_stmt *stmt;

   /* Block */
   BLOCK_DB *block_db;
   BLOCK_INFO **block_info = NULL;;
   BLOCK_INFO *new_block_info = NULL;

   block_db = dedup_volume->block_db_list;

   while(block_db != NULL)
   {
      if(block_db->digest_db)
      {
         const char *sql = "SELECT id, digest FROM block";
         rc = sqlite3_prepare(block_db->digest_db, sql, strlen(sql), &stmt, NULL);
         if( rc == SQLITE_OK )
         {
            rc = sqlite3_step(stmt);
            while(rc == SQLITE_ROW) 
            {
               new_block_info = (BLOCK_INFO *)malloc(sizeof(BLOCK_INFO));              
               new_block_info->block_db_id = block_db->id;
               new_block_info->block_id = sqlite3_column_int64(stmt, 0);
               memcpy(&(new_block_info->digest[0]), sqlite3_column_blob(stmt, 1), 32);
               new_block_info->left = NULL;
               new_block_info->right = NULL;
                           
               if(dedup_volume->block_info_tree == NULL)
               {
                  dedup_volume->block_info_tree = new_block_info;
               }
               else
               {
                  if(get_block_info(dedup_volume->block_info_tree, new_block_info->digest, block_info) == false)
                  {
                     (*block_info) = new_block_info;
                  }
                  else
                  {
                     /* Hash collision */
                     free(new_block_info);
                     new_block_info = NULL;
                  }
               }
               rc = sqlite3_step(stmt);
            }
            sqlite3_finalize(stmt);
            if( rc != SQLITE_DONE ) 
            {
               Dmsg(ctx, dbglvl, "dedup-sd: load_block_info_tree an error occured during the query on digest_db Id=%d\n", block_db->id); 
               retval = false;
               break;
            }
         }
         else 
         {
            Dmsg(ctx, dbglvl, "dedup-sd: load_block_info_tree can not get digest from digest_db Id=%d\n", block_db->id);
            retval = false;
            break;
         }
      }
      else
      {
         Dmsg(ctx, dbglvl, "dedup-sd: load_block_info_tree digest_db not available Id=%d\n", block_db->id);
         retval = false;
         break;
      }
      
      block_db = block_db->next;
   }
   
   return retval;
}
