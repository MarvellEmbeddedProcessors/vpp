/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vppinfra/unix.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <http_static_l4/http_static.h>
#include <limits.h>

#include <vppinfra/bihash_template.c>
#include <ctype.h>

#define HTTP_CONNECT "Connection:"

#define HTTP_CONN_LEN  (sizeof (HTTP_CONNECT) - 1)
#define HTTP_CONN_KA   "Keep-Alive"
#define HTTP_CONN_CL   "Close"
#define HTTP_CONN_CT_L "Content-Length: "
#define HTTP_VER_1_0   "HTTP/1.0"

#define HTTP_BODY_PREFIX "\r\n\r\n"
#define HTTP_201	 "HTTP/1.1 201 OK\r\n"
#define HTTP_201_LEN	 (sizeof (HTTP_201) - 1)
#define HTTP_200	 "HTTP/1.1 200 OK\r\n"
#define HTTP_200_LEN	 (sizeof (HTTP_200) - 1)

#define IND_HTML     "index.html"
#define IND_HTML_LEN (sizeof (IND_HTML) - 1)

#define HTTP_SESSION_CLOSED INT_MAX

/** @file static_server.c
 *  Static http server, sufficient to
 *  serve .html / .css / .js content.
 */
/*? %%clicmd:group_label Static HTTP Server %% ?*/

#define HTTP_FIFO_DEF_THRESH (64 << 10)

http_static_l4_server_main_t http_static_l4_server_main;

/** \brief Format the called-from enum
 */

static u8 *
format_state_machine_called_from (u8 *s, va_list *args)
{
  http_state_machine_called_from_t cf =
    va_arg (*args, http_state_machine_called_from_t);
  char *which = "bogus!";

  switch (cf)
    {
    case CALLED_FROM_RX:
      which = "from rx";
      break;
    case CALLED_FROM_TX:
      which = "from tx";
      break;
    case CALLED_FROM_TIMER:
      which = "from timer";
      break;

    default:
      break;
    }

  s = format (s, "%s", which);
  return s;
}

/** \brief Acquire reader lock on the sessions pools
 */
static void
http_static_server_thr_sessions_reader_lock (u32 thread_index)
{
  clib_rwlock_reader_lock (
    &http_static_l4_server_main.thr_sessions_lock[thread_index]);
}

/** \brief Drop reader lock on the sessions pools
 */
static void
http_static_server_thr_sessions_reader_unlock (u32 thread_index)
{
  clib_rwlock_reader_unlock (
    &http_static_l4_server_main.thr_sessions_lock[thread_index]);
}

/** \brief Acquire writer lock on the sessions pools
 */
static void
http_static_server_thr_sessions_writer_lock (u32 thread_index)
{
  clib_rwlock_writer_lock (
    &http_static_l4_server_main.thr_sessions_lock[thread_index]);
}

/** \brief Drop writer lock on the sessions pools
 */
static void
http_static_server_thr_sessions_writer_unlock (u32 thread_index)
{
  clib_rwlock_writer_unlock (
    &http_static_l4_server_main.thr_sessions_lock[thread_index]);
}

static void
http_static_server_all_sessions_writer_unlock (void)
{
  u32 thr_index;
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  /* Lock sessions of all threads */
  for (thr_index = 0; thr_index <= vec_len (hsm->thr_sessions_lock);
       thr_index++)
    http_static_server_thr_sessions_writer_unlock (thr_index);
}

static void
http_static_server_all_sessions_writer_lock (void)
{
  u32 thr_index;
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  /* Lock sessions of all threads */
  for (thr_index = 0; thr_index <= vec_len (hsm->thr_sessions_lock);
       thr_index++)
    http_static_server_thr_sessions_writer_lock (thr_index);
}

static void
http_static_server_all_sessions_reader_unlock (void)
{
  u32 thr_index;
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  /* Unlock sessions of all threads */
  for (thr_index = 0; thr_index <= vec_len (hsm->thr_sessions_lock);
       thr_index++)
    http_static_server_thr_sessions_reader_unlock (thr_index);
}

static void
http_static_server_all_sessions_reader_lock (void)
{
  u32 thr_index;
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  /* Lock sessions of all threads */
  for (thr_index = 0; thr_index <= vec_len (hsm->thr_sessions_lock);
       thr_index++)
    http_static_server_thr_sessions_reader_lock (thr_index);
}

/** \brief Start a session cleanup timer
 */
static void
http_static_server_session_timer_start (http_session_t *hs)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  u32 hs_handle;

  /* The session layer may fire a callback at a later date... */
  if (!pool_is_free (hsm->sessions[hs->thread_index], hs))
    {
      hs_handle = hs->thread_index << 24 | hs->session_index;
      clib_spinlock_lock (&http_static_l4_server_main.tw_lock);
      hs->timer_handle = tw_timer_start_2t_1w_2048sl (
	&http_static_l4_server_main.tw, hs_handle, 0, 60);
      clib_spinlock_unlock (&http_static_l4_server_main.tw_lock);
    }
}

/** \brief stop a session cleanup timer
 */
static void
http_static_server_session_timer_stop (http_session_t *hs)
{
  if (hs->timer_handle == ~0)
    return;
  clib_spinlock_lock (&http_static_l4_server_main.tw_lock);
  tw_timer_stop_2t_1w_2048sl (&http_static_l4_server_main.tw,
			      hs->timer_handle);
  clib_spinlock_unlock (&http_static_l4_server_main.tw_lock);
}

/** \brief Allocate an http session
 */
static http_session_t *
http_static_server_session_alloc (u32 thread_index)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  http_session_t *hs = NULL;

  pool_get_aligned_zero (hsm->sessions[thread_index], hs, 0);
  hs->session_index = hs - hsm->sessions[thread_index];
  hs->thread_index = thread_index;
  hs->timer_handle = ~0;
  hs->cache_pool_index = ~0;
  return hs;
}

/** \brief Get an http session by index
 */
static http_session_t *
http_static_server_session_get (u32 thread_index, u32 hs_index)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  if (pool_is_free_index (hsm->sessions[thread_index], hs_index))
    return 0;
  return pool_elt_at_index (hsm->sessions[thread_index], hs_index);
}

/** \brief Free an http session
 */
static void
http_static_server_session_free (http_session_t *hs)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  /* Make sure the timer is stopped... */
  http_static_server_session_timer_stop (hs);
  pool_put (hsm->sessions[hs->thread_index], hs);

  if (CLIB_DEBUG)
    {
      u32 save_thread_index;
      save_thread_index = hs->thread_index;
      /* Poison the entry, preserve timer state and thread index */
      memset (hs, 0xfa, sizeof (*hs));
      hs->timer_handle = ~0;
      hs->thread_index = save_thread_index;
    }
}

/** \brief add a session to the vpp < -- > http session index map
 */
static void
http_static_server_session_lookup_add (u32 thread_index, u32 s_index,
				       u32 hs_index)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  vec_validate (hsm->session_to_http_session[thread_index], s_index);
  hsm->session_to_http_session[thread_index][s_index] = hs_index;
}

/** \brief Remove a session from the vpp < -- > http session index map
 */
static void
http_static_server_session_lookup_del (u32 thread_index, u32 s_index)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  hsm->session_to_http_session[thread_index][s_index] = ~0;
}

/** \brief lookup a session in the vpp < -- > http session index map
 */

static http_session_t *
http_static_server_session_lookup (u32 thread_index, u32 s_index)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  u32 hs_index;

  if (s_index < vec_len (hsm->session_to_http_session[thread_index]))
    {
      hs_index = hsm->session_to_http_session[thread_index][s_index];
      return http_static_server_session_get (thread_index, hs_index);
    }
  return 0;
}

/** \brief Detach cache entry from session
 */

static void
http_static_server_detach_cache_entry (http_session_t *hs)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  file_data_cache_t *ep;

  /*
   * Decrement cache pool entry reference count
   * Note that if e.g. a file lookup fails, the cache pool index
   * won't be set
   */
  if (hs->cache_pool_index != ~0)
    {
      ep = pool_elt_at_index (hsm->cache_pool, hs->cache_pool_index);
      ep->inuse--;
      if (hsm->debug_level > 1)
	clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
		      ep->inuse);
    }
  hs->cache_pool_index = ~0;
  if (hs->free_data)
    vec_free (hs->data);
  hs->data = 0;
  hs->data_offset = 0;
  hs->free_data = 0;
  hs->path[0] = 0;
}

/** \brief Disconnect a session
 */
static void
http_static_server_session_disconnect (http_session_t *hs)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = hs->vpp_session_handle;
  a->app_index = http_static_l4_server_main.app_index;
  vnet_disconnect_session (a);
}

/** \brief http error boilerplate
 */
static const char *http_error_template = "HTTP/1.1 %s\r\n"
					 "Date: %U GMT\r\n"
					 "Content-Type: text/html\r\n"
					 "Connection: close\r\n"
					 "Pragma: no-cache\r\n"
					 "Content-Length: 0\r\n\r\n";

#define HTTP_RESPONSE_STR_MAX_SZ 512
/** \brief http response boilerplate
 */
static const char *http_response_template = "Date: %s GMT\r\n"
					    "Expires: %s GMT\r\n"
					    "Server: VPP Static\r\n"
					    "Content-Type: %s\r\n"
					    "Content-Length: %d\r\n\r\n";

/** \brief receive http data
    @param hs - http session
    @return -1 failed, 0 for success, 1 partly successful.
*/
static u32
static_receive_data (http_session_t *hs)
{
  u32 max_dequeue;
  int n_read;

  max_dequeue = svm_fifo_max_dequeue (hs->rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    {
      return -1;
    }

  n_read = app_recv_stream_raw (hs->rx_fifo, &hs->data[hs->data_offset],
				max_dequeue, 0, 0 /* peek */);
  hs->data_offset += n_read;
  if (n_read != max_dequeue)
    clib_warning ("WARNING: max_dequeue %d bytes while read only %d bytes",
		  max_dequeue, n_read);
  if (!svm_fifo_is_empty (hs->rx_fifo))
    return 1;

  svm_fifo_unset_event (hs->rx_fifo);
  return 0;
}

/** \brief send http data
    @param hs - http session
    @param data - the data vector to transmit
    @param length - length of data
    @param offset - transmit offset for this operation
    @return offset for next transmit operation, may be unchanged w/ full fifo
*/

static u32
static_send_data (http_session_t *hs, u8 *data, u32 length, u32 offset)
{
  u32 bytes_to_send;
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  bytes_to_send = length - offset;

  while (bytes_to_send > 0)
    {
      int actual_transfer;

      actual_transfer = svm_fifo_enqueue (
	hs->tx_fifo, clib_min (bytes_to_send, 4 << 20), data + offset);

      /* Made any progress? */
      if (actual_transfer <= 0)
	{
	  if (hsm->debug_level > 0 && bytes_to_send > 0)
	    clib_warning ("WARNING: still %d bytes to send", bytes_to_send);
	  return offset;
	}
      else
	{
	  offset += actual_transfer;
	  bytes_to_send -= actual_transfer;

	  if (hsm->debug_level && bytes_to_send > 0)
	    clib_warning ("WARNING: still %d bytes to send", bytes_to_send);

	  if (svm_fifo_set_event (hs->tx_fifo))
	    session_send_io_evt_to_thread (hs->tx_fifo,
					   SESSION_IO_EVT_TX_FLUSH);
	  return offset;
	}
    }
  /* NOTREACHED */
  return ~0;
}

/** \brief Send an http error string
    @param hs - the http session
    @param str - the error string, e.g. "404 Not Found"
*/
static void
send_error (http_session_t *hs, char *str)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  u8 *data;
  f64 now;

  now = clib_timebase_now (&hsm->timebase);
  data = format (0, http_error_template, str, format_clib_timebase_time, now);
  static_send_data (hs, data, vec_len (data), 0);
  vec_free (data);
}

/** \brief Retrieve data from the application layer
 */
static int
session_rx_request (http_session_t *hs)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  u32 max_dequeue, cursize;
  int n_read;

  max_dequeue = svm_fifo_max_dequeue (hs->rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return -1;

  cursize = vec_len (hs->rx_buf);
  if (vec_mem_size (hs->rx_buf) == 0)
    vec_pop2 (hsm->rx_buf_pool[hs->thread_index], hs->rx_buf);

  vec_validate (hs->rx_buf, cursize + max_dequeue - 1);
  n_read = app_recv_stream_raw (hs->rx_fifo, hs->rx_buf + cursize, max_dequeue,
				0, 0 /* peek */);
  ASSERT (n_read == max_dequeue);
  if (svm_fifo_is_empty (hs->rx_fifo))
    svm_fifo_unset_event (hs->rx_fifo);

  vec_set_len (hs->rx_buf, cursize + n_read);
  return 0;
}

/** \brief Sanity-check the forward and reverse LRU lists
 */
static inline void
lru_validate (http_static_l4_server_main_t *hsm)
{
#if CLIB_DEBUG > 0
  f64 last_timestamp;
  u32 index;
  int i;
  file_data_cache_t *ep;

  last_timestamp = 1e70;
  for (i = 1, index = hsm->first_index; index != ~0;)
    {
      ep = pool_elt_at_index (hsm->cache_pool, index);
      index = ep->next_index;
      /* Timestamps should be smaller (older) as we walk the fwd list */
      if (ep->last_used > last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f",
			ep - hsm->cache_pool, i, ep->last_used,
			last_timestamp);
	}
      last_timestamp = ep->last_used;
      i++;
    }

  last_timestamp = 0.0;
  for (i = 1, index = hsm->last_index; index != ~0;)
    {
      ep = pool_elt_at_index (hsm->cache_pool, index);
      index = ep->prev_index;
      /* Timestamps should be larger (newer) as we walk the rev list */
      if (ep->last_used < last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f",
			ep - hsm->cache_pool, i, ep->last_used,
			last_timestamp);
	}
      last_timestamp = ep->last_used;
      i++;
    }
#endif
}

/** \brief Remove a data cache entry from the LRU lists
 */
static inline void
lru_remove (http_static_l4_server_main_t *hsm, file_data_cache_t *ep)
{
  file_data_cache_t *next_ep, *prev_ep;
  u32 ep_index;

  lru_validate (hsm);

  ep_index = ep - hsm->cache_pool;

  /* Deal with list heads */
  if (ep_index == hsm->first_index)
    hsm->first_index = ep->next_index;
  if (ep_index == hsm->last_index)
    hsm->last_index = ep->prev_index;

  /* Fix next->prev */
  if (ep->next_index != ~0)
    {
      next_ep = pool_elt_at_index (hsm->cache_pool, ep->next_index);
      next_ep->prev_index = ep->prev_index;
    }
  /* Fix prev->next */
  if (ep->prev_index != ~0)
    {
      prev_ep = pool_elt_at_index (hsm->cache_pool, ep->prev_index);
      prev_ep->next_index = ep->next_index;
    }
  lru_validate (hsm);
}

/** \brief Add an entry to the LRU lists, tag w/ supplied timestamp
 */
#if 0
static inline void
lru_add (http_static_l4_server_main_t *hsm, file_data_cache_t *ep, f64 now)
{
  file_data_cache_t *next_ep;
  u32 ep_index;

  lru_validate (hsm);

  ep_index = ep - hsm->cache_pool;

  /*
   * Re-add at the head of the forward LRU list,
   * tail of the reverse LRU list
   */
  if (hsm->first_index != ~0)
    {
      next_ep = pool_elt_at_index (hsm->cache_pool, hsm->first_index);
      next_ep->prev_index = ep_index;
    }

  ep->prev_index = ~0;

  /* ep now the new head of the LRU forward list */
  ep->next_index = hsm->first_index;
  hsm->first_index = ep_index;

  /* single session case: also the tail of the reverse LRU list */
  if (hsm->last_index == ~0)
    hsm->last_index = ep_index;
  ep->last_used = now;

  lru_validate (hsm);
}
#endif
/** \brief Remove and re-add a cache entry from/to the LRU lists
 */
#if 0
static inline void
lru_update (http_static_l4_server_main_t *hsm, file_data_cache_t *ep, f64 now)
{
  lru_remove (hsm, ep);
  lru_add (hsm, ep, now);
}
#endif
/** \brief Session-layer (main) data rx callback.
    Parse the http request, and reply to it.
    Future extensions might include POST processing, active content, etc.
*/

/* svm_fifo_add_want_deq_ntf (tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL)
get shoulder-tap when transport dequeues something, set in
xmit routine. */

/** \brief closed state - should never really get here
 */
static int
state_closed (session_t *s, http_session_t *hs,
	      http_state_machine_called_from_t cf)
{
  clib_warning ("WARNING: http session %d, called from %U", hs->session_index,
		format_state_machine_called_from, cf);
  return -1;
}

static void
close_session (http_session_t *hs)
{
  http_static_server_session_timer_stop (hs);
  hs->timer_handle = ~0;
  http_static_server_session_disconnect (hs);
}

/** \brief Register a builtin GET or POST handler
 */
__clib_export void
http_static_l4_server_register_builtin_handler (void *fp, char *url,
						int request_type)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  uword *p, *builtin_table;

  builtin_table = (request_type == HTTP_BUILTIN_METHOD_GET) ?
			  hsm->get_url_handlers :
			  hsm->post_url_handlers;

  p = hash_get_mem (builtin_table, url);

  if (p)
    {
      clib_warning ("WARNING: attempt to replace handler for %s '%s' ignored",
		    (request_type == HTTP_BUILTIN_METHOD_GET) ? "GET" : "POST",
		    url);
      return;
    }

  hash_set_mem (builtin_table, url, (uword) fp);

  /*
   * Need to update the hash table pointer in http_static_l4_server_main
   * in case we just expanded it...
   */
  if (request_type == HTTP_BUILTIN_METHOD_GET)
    hsm->get_url_handlers = builtin_table;
  else
    hsm->post_url_handlers = builtin_table;
}

static int
v_find_index (u8 *vec, char *str)
{
  int start_index;
  u32 slen = (u32) strnlen_s_inline (str, 16);
  u32 vlen = vec_len (vec);

  ASSERT (slen > 0);

  if (vlen <= slen)
    return -1;

  for (start_index = 0; start_index < (vlen - slen); start_index++)
    {
      if (!memcmp (&vec[start_index], str, slen))
	return start_index;
    }

  return -1;
}

/** \brief Same func as above (v_find_index) just case-insensitive.
 */
static int
v_find_index_insensitive (u8 *vec, char *str, u32 start_pos)
{
  int start_index;
  u32 slen = (u32) strnlen_s_inline (str, 16);
  u32 vlen = vec_len (vec);

  ASSERT (slen > 0);

  if (PREDICT_FALSE (vlen - start_pos <= slen))
    return -1;

  for (start_index = start_pos; start_index < (vlen - slen); start_index++)
    {
      if (!strncasecmp ((const char *) &vec[start_index], str, slen))
	return start_index;
    }

  return -1;
}

/* Support files in following format : N[NN]c c=B|K|M, i.e. 1B,22K,789M */
static u32
parse_fileformat (u8 *vec, int *digits)
{
  u32 n_bytes = 0;
  char *endptr;

  /* Avoid vpp format() function, it uses spinlocks. */
  if (vec != NULL)
    {
      n_bytes = (u32) strtol ((char *) vec, &endptr, 10);
    }
  else
    clib_warning ("vec is null");
  if (n_bytes == 0)
    return 0;

  *digits = endptr - (char *) vec;

  switch (vec[*digits])
    {
    case 'B':
      break;
    case 'K':
      n_bytes <<= 10;
      break;
    case 'M':
      n_bytes <<= 20;
      break;
    default:
      n_bytes = 0;
    }
  return n_bytes;
}

/** \brief established state - waiting for GET, POST, etc.
 */
static int
state_established (session_t *s, http_session_t *hs,
		   http_state_machine_called_from_t cf)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  u8 *request = 0;
  int i, c, p, rv;
  u8 *nrp = NULL; /* new request pointer */
  u8 request_type = HTTP_BUILTIN_METHOD_GET;
  int digits = 0;
  u32 n_bytes = 0, num_lines, remainder;
  u32 pcl = 0; /* Post Content Length */
  u32 pfc = 0; /* Post First Content */
  const char *line =
    "001 002 003 004 005 006 007 008 009 010 011 012 013 014 015 016\n";
  u8 line_len = HTTP_STAT_LINE_LEN;
  u8 *v = NULL;
  u8 *key = NULL;
  u8 *endptr;

  ASSERT (strlen (line) == HTTP_STAT_LINE_LEN);

  /* Read data from the sessison layer */
  rv = session_rx_request (hs);

  /* No data? Odd, but stay in this state and await further instructions */
  if (rv)
    return 0;

  /* Process the client request */
  request = hs->rx_buf;
  if (vec_len (request) < 8)
    {
      if (hsm->debug_level > 1)
	clib_warning ("http request:%s too short", request);
      send_error (hs, "400 Bad Request");
      close_session (hs);
      return -1;
    }

  if ((i = v_find_index (request, "GET ")) >= 0)
    goto find_end;
  else if ((i = v_find_index (request, "POST ")) >= 0)
    {
      request_type = HTTP_BUILTIN_METHOD_POST;
      goto find_end;
    }

  if (hsm->debug_level > 1)
    clib_warning ("Unknown http method");

  send_error (hs, "405 Method Not Allowed");
  close_session (hs);
  return -1;

find_end:
  /* Lose "GET /" or "POST /" */
  vec_delete (request,
	      (request_type == HTTP_BUILTIN_METHOD_GET) ?
		      (i + sizeof ("GET /") - 1) :
		      (i + sizeof ("POST /") - 1),
	      0);
  /* Check the HTTP version, for keepalive enabling needs. */
  if (v_find_index (request, HTTP_VER_1_0) >= 0)
    hsm->keepalive = 0;
  else
    hsm->keepalive = 1;

  /* The header connection request, define the respond */
  if ((c = v_find_index (request, HTTP_CONNECT)) >= 0)
    {
      if (v_find_index_insensitive (request, HTTP_CONN_KA,
				    c + HTTP_CONN_LEN) >= 0)
	hsm->keepalive = 1;
      else if (v_find_index_insensitive (request, HTTP_CONN_CL,
					 c + HTTP_CONN_LEN) >= 0)
	hsm->keepalive = 0;
    }

  /* Lose "GET /" or "POST /" */
  vec_delete (request, i + (sizeof ("GET /") - 1) + request_type, 0);

  /* Replace 'index.html' file with redirect_file_name
   * Relies on sizeof(redirect_file_name) < "index.html"
   */
  if (v_find_index (request, "index.html") == 0 &&
      vec_len (hsm->redirect_file_name))

    if (request_type == HTTP_BUILTIN_METHOD_POST)
      {
	/* keep size of file by Content-Length for next rx queue msg read */
	if ((p = v_find_index_insensitive (request, HTTP_CONN_CT_L,
					   i + sizeof ("POST "))) >= 0)
	  {
	    nrp = &request[p + sizeof (HTTP_CONN_CT_L) - 1];
	    pcl = (int) strtol ((char *) nrp, (char **) &endptr, 10);
	    digits = endptr - nrp;
	    if ((pcl == 0) || (digits > 8)) /* max support ~95MB. */
	      {
		clib_warning ("Requested file :%s failed length parsing)",
			      nrp);
		close_session (hs);
		return -1;
	      }
	  }
	else
	  {
	    clib_warning ("POST length file:%s is invalid\n", nrp);
	    close_session (hs);
	    return -1;
	  }
	if ((p = v_find_index_insensitive (nrp, HTTP_BODY_PREFIX,
					   (u32) (nrp - request))) < 0)
	  {
	    clib_warning ("POST body request was not found:%s is invalid\n",
			  request);
	    close_session (hs);
	    return -1;
	  }
	else
	  {
	    nrp = nrp + p + sizeof (HTTP_BODY_PREFIX) - 1;
	  }
	pfc = (vec_len (request) - (nrp - request));
      }

  /* find or read the file if we haven't done so yet. */
  if (hs->data == 0)
    {
      BVT (clib_bihash_kv) kv;
      file_data_cache_t *dp;
      u8 pl = v_find_index (request, " "); /* pl = path length */
      pl = clib_min (pl, sizeof (hs->path));

      memset (hs->path, 0, sizeof (hs->path));
      strncpy ((char *) hs->path, (const char *) request, pl);
      /* key must be vector for hash purpose */
      vec_resize (key, pl);
      clib_memcpy_fast (key, hs->path, pl);
      kv.key = (u64) key;
      if (hsm->debug_level > 1)
	clib_warning ("Using '%s' key for lookup table.\n", kv.key);

      if (hsm->debug_level > 1)
	clib_warning ("hs->path:%s, Post Content Length:%d", hs->path, pcl);

      /* If the path name already exists in the cache, or not. */
      if (BV (clib_bihash_search) (&hsm->name_to_data, &kv, &kv) == 0)
	{
	  if (hsm->debug_level > 1)
	    clib_warning ("lookup '%s' returned %lld", kv.key, kv.value);

	  /* found the data.. */
	  dp = pool_elt_at_index (hsm->cache_pool, kv.value);
	  hs->data = dp->data;
	  /* Update the cache entry, mark it in-use */
	  hs->cache_pool_index = dp - hsm->cache_pool;
	  dp->inuse++;
	  if (hsm->debug_level > 1)
	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
			  dp->inuse);
	  /* If POST request, need to put the replace info */
	  if (request_type == HTTP_BUILTIN_METHOD_POST)
	    {
	      u32 min, max = 0;
	      min = clib_min (pcl, vec_bytes (dp->data));
	      max = clib_max (pcl, vec_bytes (dp->data));
	      vec_delete (dp->data, (u32) (max - min), min);
	      clib_memcpy_fast (dp->data, nrp, pfc);
	      /* check if all data has been copied or if there is more data to
	       * receive */
	      if (pcl == pfc)
		{
		  static_send_data (hs, (u8 *) "HTTP/1.1 201 OK\r\n", 17, 0);
		  hs->session_state = HTTP_STATE_OK_SENT;
		}
	      else
		{
		  hs->data_offset = pfc;
		  hs->session_state = HTTP_STATE_RECEIVE_MORE_DATA;
		}
	    }
	}
      else
	{
	  if (hsm->debug_level > 1)
	    clib_warning ("lookup '%s' failed", kv.key);

	  /* if file not found in cache, GET request with format N[NN]C can be
	   * accepted. */
	  if (request_type == HTTP_BUILTIN_METHOD_GET)
	    {
	      n_bytes = (int) strtol ((char *) request, (char **) &endptr, 10);
	      digits = endptr - request;
	      if ((n_bytes == 0) || (digits > 3))
		{
		  clib_warning ("Requested file:%s is invalid. valid format "
				"is \"N[NN]C\", N{0-9} C{B|K|M}.\n",
				request);
		  close_session (hs);
		  return -1;
		}

	      switch (request[digits])
		{
		case 'B':
		  break;
		case 'K':
		  n_bytes <<= 10;
		  break;
		case 'M':
		  n_bytes <<= 20;
		  break;
		default:
		  clib_warning ("Requested file:%s is invalid", request);
		  close_session (hs);
		  return -1;
		}

	      /* No recycling, fail if exceeding limit */
	      if ((hsm->cache_size + n_bytes) > hsm->cache_limit)
		{
		  clib_warning ("ERROR: cache-size:%llu + file-size:%u may "
				"not exceed cache-limit:%llu",
				hsm->cache_size, n_bytes, hsm->cache_limit);
		  close_session (hs);
		  return -1;
		}
	      /* Read the "file" into memory, 64B lines */
	      vec_resize (v, n_bytes);
	      num_lines = n_bytes / line_len;
	      remainder = n_bytes % line_len;
	      for (i = 0; i < num_lines; i++)
		clib_memcpy_fast (v + i * line_len, line, strlen (line));
	      clib_memcpy_fast (v + i * line_len, line, remainder);
	    }
	  else if (request_type == HTTP_BUILTIN_METHOD_POST)
	    {
	      /* pcl is the total content to be received by the POST request,
		 pfc is the current available data (not includes headers). */
	      vec_resize (v, pcl);
	      clib_memcpy_fast (v, nrp, pfc);
	      if (pcl == pfc)
		{
		  static_send_data (hs, (u8 *) "HTTP/1.1 201 OK\r\n", 17, 0);
		  hs->session_state = HTTP_STATE_OK_SENT;
		}
	      else
		{
		  hs->session_state = HTTP_STATE_RECEIVE_MORE_DATA;
		}
	    }

	  hs->data = v;

	  /* Create a cache entry for it */
	  pool_get (hsm->cache_pool, dp);
	  memset (dp, 0, sizeof (*dp));
	  strcpy ((char *) dp->filename, (char *) hs->path);
	  dp->data = hs->data;
	  hs->cache_pool_index = dp - hsm->cache_pool;
	  dp->inuse++;
	  if (hsm->debug_level > 1)
	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
			  dp->inuse);
	  /* clib_bihash_kv_vec8_8_t compares vecs, so in current code 'key'
	   * must be a vec. Creating a vec here does not effect performance,
	   * since this is the cache-miss slowpath.
	   */
	  kv.value = dp - hsm->cache_pool;
	  /* Add to the lookup table */
	  if (hsm->debug_level > 1)
	    clib_warning ("add '%s' value %lld", kv.key, kv.value);

	  if (BV (clib_bihash_add_del) (&hsm->name_to_data, &kv,
					1 /* is_add */) < 0)
	    {
	      clib_warning ("BUG: add failed!");
	    }
	  hsm->cache_size += vec_len (dp->data);
	}
      if (hs->session_state == HTTP_STATE_OK_SENT)
	{
	  hs->data_offset = 0;
	}
      else if (hs->session_state == HTTP_STATE_RECEIVE_MORE_DATA)
	{
	  hs->data_offset = pfc;
	}
    }
  /* Keep vec-len-reset, because it was done in original code. */
  vec_reset_length (hs->rx_buf);
  if (hs->session_state == HTTP_STATE_ESTABLISHED ||
      hs->session_state == HTTP_STATE_OK_SENT)
    {
      hs->session_state = HTTP_STATE_OK_SENT;
      /* send 200 OK first */
      static_send_data (hs, (u8 *) "HTTP/1.1 200 OK\r\n", 17, 0);
    }

  return 1;
}

/** \brief receive more data state - aggregate more data from Rx fifo into the
 * allocated data cache. In this state we manage data receive progress. In case
 * no more data has been received after a while, we reattach the data cache
 * page. To receive more data we will use the static_receive_data function.
 * */
static int
state_receive_more_data (session_t *s, http_session_t *hs,
			 http_state_machine_called_from_t cf)
{
  int rv;
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  /* Continue receives data */
  rv = static_receive_data (hs);
  if (rv != 0)
    {
      return rv;
    }
  if (hs->data_offset < vec_len (hs->data))
    {
      /* No: ask for a shoulder-tap when the rx fifo has more data */
      svm_fifo_add_want_deq_ntf (hs->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      hs->session_state = HTTP_STATE_RECEIVE_MORE_DATA;
      return 0;
    }
  if (hs->data_offset == vec_len (hs->data))
    {
      /* send 201 OK first */
      static_send_data (hs, (u8 *) "HTTP/1.1 201 OK\r\n", 17, 0);
      hs->session_state = HTTP_STATE_OK_SENT;
    }

  /* Let go of the file cache entry */
  http_static_server_detach_cache_entry (hs);

  /* Finished with this receive, move to CLOSING (no keepalive),
   * or back to ESTABLISHED (keepalive). */
  if (hsm->keepalive)
    hs->session_state = HTTP_STATE_ESTABLISHED;
  else
    {
      svm_fifo_add_want_deq_ntf (hs->tx_fifo,
				 SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);
      hs->session_state = HTTP_STATE_CLOSING;
    }

  return 0;
}

static int
state_send_more_data (session_t *s, http_session_t *hs,
		      http_state_machine_called_from_t cf)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  /* Start sending data */
  hs->data_offset =
    static_send_data (hs, hs->data, vec_len (hs->data), hs->data_offset);

  /* Did we finish? */
  if (hs->data_offset < vec_len (hs->data))
    {
      /* No: ask for a shoulder-tap when the tx fifo has space */
      svm_fifo_add_want_deq_ntf (hs->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      hs->session_state = HTTP_STATE_SEND_MORE_DATA;
      return 0;
    }
  /* Finished with this transaction, move to CLOSING (no keepalive),
   * or back to ESTABLISHED (keepalive).
   */

  /* Let go of the file cache entry */
  http_static_server_detach_cache_entry (hs);
  if (hsm->keepalive)
    hs->session_state = HTTP_STATE_ESTABLISHED;
  else
    {
      svm_fifo_add_want_deq_ntf (hs->tx_fifo,
				 SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);
      hs->session_state = HTTP_STATE_CLOSING;
    }

  return 0;
}

static int
state_sent_ok (session_t *s, http_session_t *hs,
	       http_state_machine_called_from_t cf)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  char *http_type;
  u8 http_response[HTTP_RESPONSE_STR_MAX_SZ];
  f64 now;
  u32 offset;
  u8 date[CLIB_TIMEBASE_STR_MAX_SZ], expire[CLIB_TIMEBASE_STR_MAX_SZ];

  http_type = "text/html";

  if (hs->data == 0)
    {
      clib_warning ("BUG: hs->data not set for session %d", hs->session_index);
      close_session (hs);
      return 0;
    }

  /*
   * Send an http response, which needs the current time,
   * the expiration time, and the data length
   */
  now = clib_timebase_now (&hsm->timebase);
  sprintf_clib_timebase_time (date, now);
  sprintf_clib_timebase_time (expire, now + 600.0);

  sprintf ((char *) http_response, http_response_template, (char *) date,
	   (char *) expire, http_type, vec_len (hs->data));
  offset =
    static_send_data (hs, http_response, strlen ((char *) http_response), 0);
  if (offset != strlen ((char *) http_response))
    {
      clib_warning ("BUG: couldn't send response header!");
      close_session (hs);
      return 0;
    }

  /* Send data from the beginning... */
  hs->data_offset = 0;
  hs->session_state = HTTP_STATE_SEND_MORE_DATA;
  return 1;
}

static int
state_closing (session_t *s, http_session_t *hs,
	       http_state_machine_called_from_t cf)
{
  close_session (hs);
  return HTTP_SESSION_CLOSED;
}

static void *state_funcs[HTTP_STATE_N_STATES] = {
  state_closed,
  /* Waiting for GET, POST, etc. */
  state_established,
  /* Received more data */
  state_receive_more_data,
  /* Sent OK */
  state_sent_ok,
  /* Send more data */
  state_send_more_data,
  /* Sent all data, closing connection */
  state_closing
};

static inline int
http_static_server_rx_tx_callback (session_t *s,
				   http_state_machine_called_from_t cf)
{
  http_session_t *hs;
  int (*fp) (session_t *, http_session_t *, http_state_machine_called_from_t);
  int rv;

  /* Acquire a reader lock on the session table */
  http_static_server_thr_sessions_reader_lock (s->thread_index);
  hs = http_static_server_session_lookup (s->thread_index, s->session_index);

  if (!hs)
    {
      clib_warning ("No http session for thread %d session_index %d",
		    s->thread_index, s->session_index);
      http_static_server_thr_sessions_reader_unlock (s->thread_index);
      return 0;
    }

  /* Execute state machine for this session */
  do
    {
      fp = state_funcs[hs->session_state];
      rv = (*fp) (s, hs, cf);
      if (rv < 0 || rv == HTTP_SESSION_CLOSED)
	goto session_closed;
    }
  while (rv);

  /* Reset the session expiration timer */
  http_static_server_session_timer_stop (hs);
  http_static_server_session_timer_start (hs);

session_closed:
  http_static_server_thr_sessions_reader_unlock (s->thread_index);
  return 0;
}

static int
http_static_server_rx_callback (session_t *s)
{
  return http_static_server_rx_tx_callback (s, CALLED_FROM_RX);
}

static int
http_static_server_tx_callback (session_t *s)
{
  return http_static_server_rx_tx_callback (s, CALLED_FROM_TX);
}

/** \brief Session accept callback
 */

static int
http_static_server_session_accept_callback (session_t *s)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  http_session_t *hs;
  u32 thresh;

  hsm->vpp_queue[s->thread_index] =
    session_main_get_vpp_event_queue (s->thread_index);

  http_static_server_thr_sessions_writer_lock (s->thread_index);

  hs = http_static_server_session_alloc (s->thread_index);
  http_static_server_session_lookup_add (s->thread_index, s->session_index,
					 hs->session_index);
  hs->rx_fifo = s->rx_fifo;
  hs->tx_fifo = s->tx_fifo;
  hs->vpp_session_index = s->session_index;
  hs->vpp_session_handle = session_handle (s);
  hs->session_state = HTTP_STATE_ESTABLISHED;
  http_static_server_session_timer_start (hs);

  http_static_server_thr_sessions_writer_unlock (s->thread_index);

  /* The application sets a threshold for it's fifo to get notified when
   * additional data can be enqueued. We want to keep the TX fifo reasonably
   * full, however avoid entering a state where the fifo is full all the time
   * and small chunks of data are being enqueued each time.
   * If the fifo and threshold use the same size, this means that a
   * notification will be given when the fifo empties.
   */
  thresh = svm_fifo_size (hs->tx_fifo) - hsm->fifo_deq_thresh;
  svm_fifo_set_deq_thresh (hs->tx_fifo, thresh);

  s->session_state = SESSION_STATE_READY;
  return 0;
}

/** \brief Session disconnect callback
 */

static void
http_static_server_session_disconnect_callback (session_t *s)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

/** \brief Session reset callback
 */

static void
http_static_server_session_reset_callback (session_t *s)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (s);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

static int
http_static_server_session_connected_callback (u32 app_index, u32 api_context,
					       session_t *s,
					       session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static int
http_static_server_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
http_static_session_cleanup (session_t *s, session_cleanup_ntf_t ntf)
{
  http_session_t *hs;
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  http_static_server_thr_sessions_writer_lock (s->thread_index);

  hs = http_static_server_session_lookup (s->thread_index, s->session_index);
  if (!hs)
    goto done;

  http_static_server_detach_cache_entry (hs);
  http_static_server_session_lookup_del (hs->thread_index,
					 hs->vpp_session_index);

  vec_reset_length (hs->rx_buf);
  vec_add1 (hsm->rx_buf_pool[hs->thread_index], hs->rx_buf);
  http_static_server_session_free (hs);

done:
  http_static_server_thr_sessions_writer_unlock (s->thread_index);
}

/** \brief Session-layer virtual function table
 */
static session_cb_vft_t http_static_server_session_cb_vft = {
  .session_accept_callback = http_static_server_session_accept_callback,
  .session_disconnect_callback =
    http_static_server_session_disconnect_callback,
  .session_connected_callback = http_static_server_session_connected_callback,
  .add_segment_callback = http_static_server_add_segment_callback,
  .builtin_app_rx_callback = http_static_server_rx_callback,
  .builtin_app_tx_callback = http_static_server_tx_callback,
  .session_reset_callback = http_static_server_session_reset_callback,
  .session_cleanup_callback = http_static_session_cleanup,
};

static int
http_static_server_attach ()
{
  vnet_app_add_cert_key_pair_args_t *ck_pair =
    vnet_app_tls_get_test_srv_key_pair ();
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u64 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "test_http_static_server");
  a->session_cb_vft = &http_static_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hsm->prealloc_fifos;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  hsm->app_index = a->app_index;

  vnet_app_add_cert_key_pair (ck_pair);
  hsm->ckpair_index = ck_pair->index;

  return 0;
}

static int
http_static_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static int
http_static_server_listen ()
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_listen_args_t _a, *a = &_a;
  char *uri = "tcp://0.0.0.0/80";
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = hsm->app_index;

  if (hsm->uri)
    uri = (char *) hsm->uri;

  if (parse_uri (uri, &sep))
    return -1;

  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));
  if (http_static_transport_needs_crypto (a->sep_ext.transport_proto))
    {
      session_endpoint_alloc_ext_cfg (&a->sep_ext,
				      TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
      a->sep_ext.ext_cfg->crypto.ckpair_index = hsm->ckpair_index;
    }

  rv = vnet_listen (a);
  if (a->sep_ext.ext_cfg)
    clib_mem_free (a->sep_ext.ext_cfg);
  return rv;
}

static void
http_static_server_session_close_cb (void *hs_handlep)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  http_session_t *hs;
  uword hs_handle;
  hs_handle = pointer_to_uword (hs_handlep);
  hs =
    http_static_server_session_get (hs_handle >> 24, hs_handle & 0x00FFFFFF);

  if (hsm->debug_level > 1)
    clib_warning ("terminate thread %d index %d hs %llx", hs_handle >> 24,
		  hs_handle & 0x00FFFFFF, hs);
  if (!hs)
    return;
  hs->timer_handle = ~0;
  http_static_server_session_disconnect (hs);
}

/** \brief Expired session timer-wheel callback
 */
static void
http_expired_timers_dispatch (u32 *expired_timers)
{
  u32 hs_handle;
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session handle. The first bit is the timer id */
      hs_handle = expired_timers[i] & 0x7FFFFFFF;
      session_send_rpc_evt_to_thread (hs_handle >> 24,
				      http_static_server_session_close_cb,
				      uword_to_pointer (hs_handle, void *));
    }
}

/** \brief Timer-wheel expiration process
 */
static uword
http_static_server_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
			    vlib_frame_t *f)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, (uword **) &event_data);

      /* expire timers */
      clib_spinlock_lock (&http_static_l4_server_main.tw_lock);
      tw_timer_expire_timers_2t_1w_2048sl (&hsm->tw, now);
      clib_spinlock_unlock (&http_static_l4_server_main.tw_lock);

      vec_reset_length (event_data);
    }
  return 0;
}

VLIB_REGISTER_NODE (http_static_server_process_node) = {
  .function = http_static_server_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "static-http-server-process",
  .state = VLIB_NODE_STATE_DISABLED,
};

static int
http_static_server_create (vlib_main_t *vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  u32 num_threads, i;
  vlib_node_t *n;

  num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (hsm->vpp_queue, num_threads - 1);
  vec_validate (hsm->sessions, num_threads - 1);
  vec_validate (hsm->session_to_http_session, num_threads - 1);
  vec_validate (hsm->thr_sessions_lock, num_threads - 1);
  vec_validate (hsm->rx_buf_pool, num_threads - 1);

  for (i = 0; i <= vec_len (hsm->thr_sessions_lock); i++)
    clib_rwlock_init (&hsm->thr_sessions_lock[i]);

  clib_spinlock_init (&hsm->tw_lock);

  if (http_static_server_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (http_static_server_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  /* Init path-to-cache hash table */
  BV (clib_bihash_init) (&hsm->name_to_data, "http cache", 128, 32 << 20);

  hsm->get_url_handlers = hash_create_string (0, sizeof (uword));
  hsm->post_url_handlers = hash_create_string (0, sizeof (uword));

  /* Init timer wheel and process */
  tw_timer_wheel_init_2t_1w_2048sl (&hsm->tw, http_expired_timers_dispatch,
				    1.0 /* timer interval */, ~0);
  vlib_node_set_state (vm, http_static_server_process_node.index,
		       VLIB_NODE_STATE_POLLING);
  n = vlib_get_node (vm, http_static_server_process_node.index);
  vlib_start_process (vm, n->runtime_index);

  return 0;
}

/** \brief API helper function for vl_api_http_static_enable_t messages
 */
int
http_static_l4_server_enable (u32 fifo_size, u32 cache_limit,
			      u32 prealloc_fifos, u32 private_segment_size,
			      u8 *www_root, u8 *uri)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  int rv;

  hsm->fifo_size = fifo_size;
  hsm->cache_limit = cache_limit;
  hsm->prealloc_fifos = prealloc_fifos;
  hsm->private_segment_size = private_segment_size;
  hsm->www_root = format (0, "%s%c", www_root, 0);
  hsm->uri = format (0, "%s%c", uri, 0);

  if (vec_len (hsm->www_root) < 2)
    return VNET_API_ERROR_INVALID_VALUE;

  if (hsm->my_client_index != ~0)
    return VNET_API_ERROR_APP_ALREADY_ATTACHED;

  vnet_session_enable_disable (hsm->vlib_main, 1 /* turn on TCP, etc. */);

  rv = http_static_server_create (hsm->vlib_main);
  switch (rv)
    {
    case 0:
      break;
    default:
      vec_free (hsm->www_root);
      vec_free (hsm->uri);
      return VNET_API_ERROR_INIT_FAILED;
    }
  return 0;
}

static clib_error_t *
http_static_l4_server_create_command_fn (vlib_main_t *vm,
					 unformat_input_t *input,
					 vlib_cli_command_t *cmd)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 seg_size;
  u64 fifo_size;
  u64 fifo_deq_thresh;
  u8 *www_root = 0;
  int rv;

  hsm->prealloc_fifos = 0;
  hsm->private_segment_size = 0;
  hsm->fifo_size = 0;
  hsm->fifo_deq_thresh = HTTP_FIFO_DEF_THRESH;
  /* 10mb cache limit, before LRU occurs */
  hsm->cache_limit = 10 << 20;

  clib_warning ("Starting http_static_l4_server ...");
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_wwwroot;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "www-root %s", &www_root))
	;
      else if (unformat (line_input, "prealloc-fifos %d",
			 &hsm->prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &seg_size))
	hsm->private_segment_size = seg_size;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &fifo_size))
	{
	  if (fifo_size > UINT_MAX)
	    return clib_error_return (0, "fifo-size can't be over 4gb");
	  hsm->fifo_size =
	    (fifo_size < 1024) ? fifo_size << 10 : (u32) fifo_size;
	  vlib_cli_output (vm, "fifo-size set to :%u", hsm->fifo_size);
	}
      else if (unformat (line_input, "fifo-deq-thresh %U",
			 unformat_memory_size, &fifo_deq_thresh))
	{
	  hsm->fifo_deq_thresh = (fifo_deq_thresh < 1024) ?
					 fifo_deq_thresh << 10 :
					 (u32) fifo_deq_thresh;
	  vlib_cli_output (vm, "fifo-deq-thresh set to :%u",
			   hsm->fifo_deq_thresh);
	}
      else if (unformat (line_input, "cache-size %U", unformat_memory_size,
			 &hsm->cache_limit))
	{
	  if (hsm->cache_limit < (128 << 10))
	    {
	      return clib_error_return (0,
					"cache-size must be at least 128kb");
	    }
	}

      else if (unformat (line_input, "uri %s", &hsm->uri))
	;
      else if (unformat (line_input, "debug %d", &hsm->debug_level))
	;
      else if (unformat (line_input, "debug"))
	hsm->debug_level = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (hsm->fifo_deq_thresh > hsm->fifo_size)
    {
      return clib_error_return (
	0, "fifo-deq-thresh:%u can be bigger than fifo-size:%d",
	hsm->fifo_deq_thresh, hsm->fifo_size);
    }

  if (www_root == 0)
    {
    no_wwwroot:
      return clib_error_return (0, "Must specify www-root <path>");
    }

  if (hsm->my_client_index != (u32) ~0)
    {
      vec_free (www_root);
      return clib_error_return (0, "http server already running...");
    }

  hsm->www_root = www_root;

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */);

  rv = http_static_server_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      vec_free (hsm->www_root);
      return clib_error_return (0, "server_create returned %d", rv);
    }
  return 0;
}

/*?
 * Enable the static http server
 *
 * @cliexpar
 * This command enables the static http server. Only the www-root
 * parameter is required
 * @clistart
 * http static server www-root /tmp/www uri tcp://0.0.0.0/80 cache-size 2m
 * @cliend
 * @cliexcmd{http static server www-root <path> [prealloc-fios <nn>]
 *   [private-segment-size <nnMG>] [fifo-size <nbytes>] [uri <uri>]}
?*/
VLIB_CLI_COMMAND (http_static_l4_server_create_command, static) = {
  .path = "http static l4 server",
  .short_help =
    "http static l4 server www-root <path> [prealloc-fifos <nn>]\n"
    "[private-segment-size <nnMG>] [fifo-size <nbytes>] [uri <uri>]\n"
    "[debug [nn]]\n",
  .function = http_static_l4_server_create_command_fn,
};

/** \brief format a file cache entry
 */
u8 *
format_hsm_l4_cache_entry (u8 *s, va_list *args)
{
  file_data_cache_t *ep = va_arg (*args, file_data_cache_t *);
  f64 now = va_arg (*args, f64);

  /* Header */
  if (ep == 0)
    {
      s = format (s, "%40s%12s%20s", "File", "Size", "Age");
      return s;
    }
  s = format (s, "%40s%12lld%20.2f", ep->filename, vec_len (ep->data),
	      now - ep->last_used);
  return s;
}

u8 *
format_http_l4_session_state (u8 *s, va_list *args)
{
  http_session_state_t state = va_arg (*args, http_session_state_t);
  char *state_string = "bogus!";

  switch (state)
    {
    case HTTP_STATE_CLOSED:
      state_string = "closed";
      break;
    case HTTP_STATE_ESTABLISHED:
      state_string = "established";
      break;
    case HTTP_STATE_RECEIVE_MORE_DATA:
      state_string = "received";
      break;
    case HTTP_STATE_OK_SENT:
      state_string = "ok sent";
      break;
    case HTTP_STATE_SEND_MORE_DATA:
      state_string = "send more data";
      break;
    case HTTP_STATE_CLOSING:
      state_string = "closing";
      break;
    default:
      break;
    }

  return format (s, "%s", state_string);
}

u8 *
format_http_l4_session (u8 *s, va_list *args)
{
  http_session_t *hs = va_arg (*args, http_session_t *);
  int verbose = va_arg (*args, int);

  s = format (s, "[%d]: state %U", hs->session_index,
	      format_http_l4_session_state, hs->session_state);
  if (verbose > 0)
    {
      s = format (s, "\n path %s, data length %u, data_offset %u", hs->path,
		  vec_len (hs->data), hs->data_offset);
    }
  return s;
}

static clib_error_t *
http_show_static_l4_server_command_fn (vlib_main_t *vm,
				       unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  file_data_cache_t *ep, **entries = 0;
  int verbose = 0;
  int show_cache = 0;
  int show_sessions = 0;
  u32 index;
  f64 now;

  if (hsm->www_root == 0)
    return clib_error_return (0, "Static server disabled");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "cache"))
	show_cache = 1;
      else if (unformat (input, "sessions"))
	show_sessions = 1;
      else
	break;
    }

  if ((show_cache + show_sessions) == 0)
    return clib_error_return (0, "specify one or more of cache, sessions");

  if (show_cache)
    {
      if (verbose == 0)
	{
	  vlib_cli_output (
	    vm,
	    "www_root %s, cache size %lld bytes, limit %lld bytes, "
	    "evictions %lld",
	    hsm->www_root, hsm->cache_size, hsm->cache_limit,
	    hsm->cache_evictions);
	  return 0;
	}

      now = vlib_time_now (vm);

      vlib_cli_output (vm, "%U", format_hsm_l4_cache_entry, 0 /* header */,
		       now);

      for (index = hsm->first_index; index != ~0;)
	{
	  ep = pool_elt_at_index (hsm->cache_pool, index);
	  index = ep->next_index;
	  vlib_cli_output (vm, "%U", format_hsm_l4_cache_entry, ep, now);
	}

      vlib_cli_output (vm, "%40s%12lld", "Total Size", hsm->cache_size);

      vec_free (entries);
    }

  if (show_sessions)
    {
      u32 *session_indices = 0;
      http_session_t *hs;
      int i, j;

      /* Lock for all threads */
      http_static_server_all_sessions_reader_lock ();

      for (i = 0; i < vec_len (hsm->sessions); i++)
	{
	  pool_foreach (hs, hsm->sessions[i])
	    {
	      vec_add1 (session_indices, hs - hsm->sessions[i]);
	    }

	  for (j = 0; j < vec_len (session_indices); j++)
	    {
	      vlib_cli_output (
		vm, "%U", format_http_l4_session,
		pool_elt_at_index (hsm->sessions[i], session_indices[j]),
		verbose);
	    }
	  vec_reset_length (session_indices);
	}
      http_static_server_all_sessions_reader_unlock ();
      vec_free (session_indices);
    }
  return 0;
}

/*?
 * Display static http server l4 cache statistics
 *
 * @cliexpar
 * This command shows the contents of the static http l4 server cache
 * @clistart
 * show http static server
 * @cliend
 * @cliexcmd{show http static l4 server sessions cache [verbose [nn]]}
?*/
VLIB_CLI_COMMAND (http_show_static_l4_server_command, static) = {
  .path = "show http static l4 server",
  .short_help = "show http static l4 server sessions cache [verbose [<nn>]]",
  .function = http_show_static_l4_server_command_fn,
};

static clib_error_t *
http_clear_static_cache_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  file_data_cache_t *dp;
  u32 free_index;
  u32 busy_items = 0;
  BVT (clib_bihash_kv) kv;

  if (hsm->www_root == 0)
    return clib_error_return (0, "Static server disabled");

  /* Lock for all threads */
  http_static_server_all_sessions_reader_lock ();

  /* Walk the LRU list to find active entries */
  free_index = hsm->last_index;
  while (free_index != ~0)
    {
      dp = pool_elt_at_index (hsm->cache_pool, free_index);
      free_index = dp->prev_index;
      /* Which could be in use... */
      if (dp->inuse)
	{
	  busy_items++;
	  free_index = dp->next_index;
	  continue;
	}
      kv.key = (u64) (dp->filename);
      kv.value = ~0ULL;
      if (BV (clib_bihash_add_del) (&hsm->name_to_data, &kv, 0 /* is_add */) <
	  0)
	{
	  clib_warning ("BUG: cache clear delete '%s' FAILED!", dp->filename);
	}

      lru_remove (hsm, dp);
      hsm->cache_size -= vec_len (dp->data);
      hsm->cache_evictions++;
      dp->filename[0] = 0;
      vec_free (dp->data);
      if (hsm->debug_level > 1)
	clib_warning ("pool put index %d", dp - hsm->cache_pool);
      pool_put (hsm->cache_pool, dp);
      free_index = hsm->last_index;
    }
  http_static_server_all_sessions_reader_unlock ();
  if (busy_items > 0)
    vlib_cli_output (vm, "Note: %d busy items still in cache...", busy_items);
  else
    vlib_cli_output (vm, "Cache cleared...");
  return 0;
}

/*?
 * Clear the static http l4 server cache, to force the server to
 * reload content from backing files
 *
 * @cliexpar
 * This command clear the static http server cache
 * @clistart
 * clear http static cache
 * @cliend
 * @cliexcmd{clear http static l4 cache}
?*/
VLIB_CLI_COMMAND (clear_http_static_l4_cache_command, static) = {
  .path = "clear http static l4 cache",
  .short_help = "clear http static l4 cache",
  .function = http_clear_static_cache_command_fn,
};

static clib_error_t *
http_set_static_l4_redirect_command_fn (vlib_main_t *vm,
					unformat_input_t *input,
					vlib_cli_command_t *cmd)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *redirect_file = NULL;
  int digits = 0;
  u32 n_bytes, num_m_args = 0;

  if (hsm->www_root == 0)
    return clib_error_return (0, "Static server disabled");

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "file %s", &redirect_file))
	num_m_args++;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  if (num_m_args != 1)
    return clib_error_return (0, "Too many params");

  if (redirect_file == NULL)
    return clib_error_return (0, "No file name", redirect_file);
  else
    clib_warning ("File Name : %s", redirect_file);

  n_bytes = parse_fileformat (redirect_file, &digits);
  if (n_bytes == 0 || digits > 3)
    return clib_error_return (0, "Bad File : %s, n_bytes=%u, digits=%u",
			      redirect_file, n_bytes, digits);

  redirect_file[digits + 1] = '\0';

  /* Lock for all threads */
  http_static_server_all_sessions_writer_lock ();
  strcpy (hsm->redirect_file_name, (char *) redirect_file);
  http_static_server_all_sessions_writer_unlock ();
  vlib_cli_output (vm, "redirect index.html to File Name : %s", redirect_file);
  vec_free (redirect_file);
  return 0;
}

VLIB_CLI_COMMAND (http_set_static_l4_redirect_command, static) = {
  .path = "set http static l4 redirect",
  .short_help = "set http static l4 redirect file <filename>",
  .function = http_set_static_l4_redirect_command_fn,
};

static clib_error_t *
http_static_l4_server_main_init (vlib_main_t *vm)
{
  http_static_l4_server_main_t *hsm = &http_static_l4_server_main;

  hsm->my_client_index = ~0;
  hsm->vlib_main = vm;
  hsm->first_index = hsm->last_index = ~0;

  clib_timebase_init (&hsm->timebase, 0 /* GMT */, CLIB_TIMEBASE_DAYLIGHT_NONE,
		      &vm->clib_time /* share the system clock */);

  return 0;
}

VLIB_INIT_FUNCTION (http_static_l4_server_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
