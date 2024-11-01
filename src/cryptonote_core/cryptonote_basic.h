// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/variant.hpp>
#include <boost/functional/hash/hash.hpp>
#include <iostream>
#include <vector>
#include <cstring>  // memcmp
#include <sstream>
#include "serialization/serialization.h"
#include "serialization/variant.h"
#include "serialization/vector.h"
#include "serialization/binary_archive.h"
#include "serialization/crypto.h"
#include "serialization/keyvalue_serialization.h" // epee named serialization
#include "string_tools.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "misc_language.h"
#include "tx_extra.h"
#include "ringct/rctTypes.h"
#include "cryptonote_protocol/blobdatatype.h"


namespace cryptonote
{
  struct block;
  class transaction;
  class transaction_prefix;
  struct tx_extra_merge_mining_tag;

  // Implemented in cryptonote_format_utils.cpp
  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h);
  void get_blob_hash(const blobdata& blob, crypto::hash& res);
  bool get_mm_tag_from_extra(const std::vector<uint8_t>& tx, tx_extra_merge_mining_tag& mm_tag);

  const static crypto::hash null_hash = AUTO_VAL_INIT(null_hash);
  const static crypto::public_key null_pkey = AUTO_VAL_INIT(null_pkey);

  typedef std::vector<crypto::signature> ring_signature;

  enum salvium_transaction_type
  {
    UNSET = 0,
    MINER = 1,
    PROTOCOL = 2,
    TRANSFER = 3,
    CONVERT = 4,
    BURN = 5,
    STAKE = 6,
    RETURN = 7,
    MAX = 7
  };
  
  /* outputs */

  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  // SALVIUM
  // outputs <= HF_VERSION_VIEW_TAGS
  struct txout_to_key
  {
    txout_to_key() { }
    txout_to_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time) :
      key(_key), asset_type(_asset_type), unlock_time(_unlock_time) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
    END_SERIALIZE()
  };

  // outputs >= HF_VERSION_VIEW_TAGS
  struct txout_to_tagged_key
  {
    txout_to_tagged_key() { }
    txout_to_tagged_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time, const crypto::view_tag &_view_tag) :
      key(_key), asset_type(_asset_type), unlock_time(_unlock_time), view_tag(_view_tag) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;
    crypto::view_tag view_tag; // optimization to reduce scanning time

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
      FIELD(view_tag)
    END_SERIALIZE()
  };

  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(asset_type)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };
  
  typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key> txin_v;

  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_to_key, txout_to_tagged_key> txout_target_v;

  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  class transaction_prefix
  {

  public:
    enum BLOB_TYPE blob_type;
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    //extra
    std::vector<uint8_t> extra;

    // SALVIUM-SPECIFIC FIELDS
    // TX type
    cryptonote::salvium_transaction_type type;
    // Return address
    crypto::public_key return_address;
    // Return address list (must be at least 1 and at most BULLETPROOF_MAX_OUTPUTS-1 - the "-1" is for the change output)
    std::vector<crypto::public_key> return_address_list;
    //return_address_change_mask
    std::vector<uint8_t> return_address_change_mask;
    // Return TX public key
    crypto::public_key return_pubkey;
    // Source asset type
    std::string source_asset_type;
    // Destination asset type (this is only necessary for CONVERT transactions)
    std::string destination_asset_type;
    // Circulating supply information - already provided by Haven
    uint64_t amount_burnt;
    // Slippage limit
    uint64_t amount_slippage_limit;

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      if(version == 0 || CURRENT_TRANSACTION_VERSION < version) return false;
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      FIELD(extra)
      VARINT_FIELD(type)
      if (type != cryptonote::salvium_transaction_type::PROTOCOL) {
        VARINT_FIELD(amount_burnt)
        if (type != cryptonote::salvium_transaction_type::MINER) {
          if (type == cryptonote::salvium_transaction_type::TRANSFER && version >= TRANSACTION_VERSION_N_OUTS) {
            FIELD(return_address_list)
            FIELD(return_address_change_mask)
          } else {
            FIELD(return_address)
            FIELD(return_pubkey)
          }
          FIELD(source_asset_type)
          FIELD(destination_asset_type)
          VARINT_FIELD(amount_slippage_limit)
        }
      }
    
    END_SERIALIZE()


  protected:
    transaction_prefix() : blob_type(BLOB_TYPE_CRYPTONOTE) {}
  };

  class transaction: public transaction_prefix
  {
  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;

    transaction();
    virtual ~transaction();
    void set_null();

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<transaction_prefix *>(this))

      if (version == 1 && blob_type != BLOB_TYPE_CRYPTONOTE2 && blob_type != BLOB_TYPE_CRYPTONOTE3)
      {
        ar.tag("signatures");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures);
        bool signatures_not_expected = signatures.empty();
        if (!signatures_not_expected && vin.size() != signatures.size())
          return false;

        for (size_t i = 0; i < vin.size(); ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (signatures_not_expected)
          {
            if (0 == signature_size)
              continue;
            else
              return false;
          }

          PREPARE_CUSTOM_VECTOR_SERIALIZATION(signature_size, signatures[i]);
          if (signature_size != signatures[i].size())
            return false;

          FIELDS(signatures[i]);

          if (vin.size() - i > 1)
            ar.delimit_array();
        }
        ar.end_array();
      }
      else
      {
        ar.tag("rct_signatures");
        if (!vin.empty())
        {
          ar.begin_object();
          bool r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.stream().good()) return false;
          ar.end_object();
          if (rct_signatures.type != rct::RCTTypeNull)
          {
            ar.tag("rctsig_prunable");
            ar.begin_object();
            r = rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin.size(), vout.size(),
                                                           vin.size() > 0 && vin[0].type() == typeid(txin_to_key) ? boost::get<txin_to_key>(vin[0]).key_offsets.size() - 1 : 0);
            if (!r || !ar.stream().good()) return false;
            ar.end_object();
          }
        }
      }
    END_SERIALIZE()

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };

  inline
  transaction::transaction()
  {
    set_null();
  }

  inline
  transaction::~transaction()
  {
    //set_null();
  }

  inline
  void transaction::set_null()
  {
    version = 0;
    unlock_time = 0;
    vin.clear();
    vout.clear();
    extra.clear();
    signatures.clear();

    // Salvium-specific fields
    type = cryptonote::salvium_transaction_type::UNSET;
    return_address = null_pkey;
    return_address_list.clear();
    return_address_change_mask.clear();
    return_pubkey = null_pkey;
    source_asset_type.clear();
    destination_asset_type.clear();
    amount_burnt = 0;
    amount_slippage_limit = 0;
  }

  inline
  size_t transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor : public boost::static_visitor<size_t>
    {
      size_t operator()(const txin_gen& txin) const{return 0;}
      size_t operator()(const txin_to_script& txin) const{return 0;}
      size_t operator()(const txin_to_scripthash& txin) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.key_offsets.size();}
    };

    return boost::apply_visitor(txin_signature_size_visitor(), tx_in);
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

  struct block_header
  {
    enum BLOB_TYPE blob_type;

    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash prev_id;
    uint32_t nonce;

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(prev_id)
      FIELD(nonce)

    END_SERIALIZE()
  };

  struct block: public block_header
  {
    transaction miner_tx;
    transaction protocol_tx;
    std::vector<crypto::hash> tx_hashes;

    void set_blob_type(enum BLOB_TYPE bt) { miner_tx.blob_type = protocol_tx.blob_type = blob_type = bt; }

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<block_header *>(this))
      FIELD(miner_tx)
      FIELD(protocol_tx)
      FIELD(tx_hashes)
    END_SERIALIZE()
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct account_public_address
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
    END_KV_SERIALIZE_MAP()
  };

  struct integrated_address {
    account_public_address adr;
    crypto::hash8 payment_id;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(adr)
    FIELD(payment_id)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(adr)
    KV_SERIALIZE(payment_id)
    END_KV_SERIALIZE_MAP()
  };
  //---------------------------------------------------------------

}

//BLOB_SERIALIZER(cryptonote::txout_to_key);
BLOB_SERIALIZER(cryptonote::txout_to_scripthash);

VARIANT_TAG(binary_archive, cryptonote::txin_gen, 0xff);
VARIANT_TAG(binary_archive, cryptonote::txin_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txin_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txin_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txout_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txout_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txout_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txout_to_tagged_key, 0x3);
VARIANT_TAG(binary_archive, cryptonote::transaction, 0xcc);
VARIANT_TAG(binary_archive, cryptonote::block, 0xbb);
