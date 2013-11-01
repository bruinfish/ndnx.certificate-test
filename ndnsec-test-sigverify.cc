/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <iostream>
#include <fstream>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/bind.hpp>
#include <cryptopp/base64.h>

#include "ndn.cxx/security/keychain.h"
#include "ndn.cxx/security/policy/simple-policy-manager.h"
#include "ndn.cxx/security/policy/identity-policy-rule.h"
#include "ndn.cxx/security/exception.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

Ptr<security::IdentityCertificate>
getCertificate(const string& fileName)
{
  istream* ifs;
  if(fileName == string("-"))
    ifs = &cin;
  else
    ifs = new ifstream(fileName.c_str());

  string str((istreambuf_iterator<char>(*ifs)),
             istreambuf_iterator<char>());

  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  Ptr<Blob> blob = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
  Ptr<Data> data = Data::decodeFromWire(blob);
  Ptr<security::IdentityCertificate> identityCertificate = Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*data));

  return identityCertificate;
}

int main(int argc, char** argv)	
{
  string signer;
  string signee;

  po::options_description desc("General Usage\n  ndnsec-test-sigverify [-h] signer signee\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("signer,r", po::value<string>(&signer), "signer file name")
    ("signee,e", po::value<string>(&signee), "signee file name")
    ;

  po::positional_options_description p;
  p.add("signer", 1).add("signee", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;
      return 1;
    }

  try{
    using namespace ndn::security;
    Ptr<IdentityCertificate> signerCert = getCertificate(signer);
    Ptr<IdentityCertificate> signeeCert = getCertificate(signee);
    
    if(PolicyManager::verifySignature(*signeeCert, signerCert->getPublicKeyInfo()))
      cerr << "verified" << endl;
    else
      cerr << "unverified" << endl;
  }catch(exception& e){
    cerr << e.what() << endl;
  }
  return 0;
}

