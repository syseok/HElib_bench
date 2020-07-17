/* Copyright (C) 2012-2017 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
#include <iostream>
#include <cassert>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <NTL/BasicThreadPool.h>
NTL_CLIENT

#include <chrono>

#include "EncryptedArray.h"
#include "FHE.h"

#include "intraSlot.h"
#include "binaryArith.h"
#include "ArgMap.h"

#ifdef DEBUG_PRINTOUT
#include "debugging.h"
#endif

static std::vector<zzX> unpackSlotEncoding; // a global variable
static bool verbose=true;


void testProduct(FHESecKey& secKey, const FHEPubKey& pubKey,long bitSize1, long bitSize2,
                 long outSize, bool bootstrap = false);
void testAdd(FHESecKey& secKey, long bitSize1, long bitSize2,
             long outSize, bool bootstrap = false);


int main(int argc, char *argv[])
{

  long outSize = 0;
 
  long nTests = 5;
  
  bool bootstrap = false;

  long tests2avoid = 1;

  // Compute the number of levels
  long bitSize=1;
  long bitSize2=128;
  long m=14351;
  // m=FindM(80, 2, 3, 2, 0, m, 0,false);
  long p=2;
  long c=3;
  long L=14;
  if (verbose) {
    cout <<"input bitSizes="<<bitSize
         <<", output size bound="<<outSize
         <<", running "<<nTests<<" tests for each function\n"
         <<"L value is "<<L<<endl;
  }

  FHEcontext context(m, p, /*r=*/1);
  buildModChain(context, L, c,/*willBeBootstrappable=*/bootstrap);
  buildUnpackSlotEncoding(unpackSlotEncoding, *context.ea);
  FHESecKey secKey(context);
  secKey.GenSecKey(64);
  const FHEPubKey& publicKey = secKey;
  addSome1DMatrices(secKey);


    if (!(tests2avoid & 4)) {
    for (long i=0; i<nTests; i++)
      
      testAdd(secKey, 1, 127, outSize, bootstrap);
    cout << "GOOD\n";
  }
  if (!(tests2avoid & 4)) {
    for (long i=0; i<nTests; i++)
      
      testProduct(secKey,publicKey, 1, 128, outSize, bootstrap);
    cout << "GOOD\n";
  }

  if (verbose) printAllTimers(cout);

  return 0;
}

void testProduct(FHESecKey& secKey,const FHEPubKey& pubKey, long bitSize, long bitSize2,
                 long outSize, bool bootstrap)
{
  std::chrono::system_clock::time_point start7 = std::chrono::system_clock::now();
  const FHEcontext& context = pubKey.getContext();
  const EncryptedArray& ea = *(context.ea);
  long mask = (outSize? ((1L<<outSize)-1) : -1); 

  long pa = RandomBits_long(bitSize);
  
  cout<<"star timing... pa is"<<pa <<endl; 
  vector<Ctxt> enca(bitSize2,Ctxt(pubKey));

  for (int i=0; i<bitSize2; i++) {	
    pubKey.Encrypt(enca[i], ZZX(pa));  
  }	
  
  ZZX PP;
    for (int k=0;k<128;k+=2)
    {
    	enca[k].multiplyBy(enca[k+1]);
    	// cout<<k<<endl;
    	
    }
    for (int k=0;k<128;k+=4)
    {
    	enca[k].multiplyBy(enca[k+2]);
    	// cout<<k<<endl;
    	
    }
    for (int k=0;k<128;k+=8)
    {
    	enca[k].multiplyBy(enca[k+4]);
    	// cout<<k<<endl;
    	
    }
    for (int k=0;k<128;k+=16)
    {
    	enca[k].multiplyBy(enca[k+8]);
    	// cout<<k<<endl;
    	
    }
    for (int k=0;k<128;k+=32)
    {
    	enca[k].multiplyBy(enca[k+16]);
    	// cout<<k<<endl;
    	
    }
    for (int k=0;k<128;k+=64)
    {
    	enca[k].multiplyBy(enca[k+32]);
    	// cout<<k<<endl;
    	
    }
    enca[0].multiplyBy(enca[64]);
    

    vector<long> res;
   secKey.Decrypt(PP,enca[0]);	  
	  long long pProd = (long long)(pa);
  
  if(PP==pProd){
   cout << "product succeeded: ";
    cout << pa<<"^"<<bitSize2<<"="<<pProd<<endl;
	}
	else
	{
		cout << "product failed: ";
	}
	
  std::chrono::duration<double> sec = std::chrono::system_clock::now() - start7;
  std::cout << "time : " << sec.count() << " seconds" << std::endl;
}

void testAdd(FHESecKey& secKey, long bitSize, long bitSize2,
             long outSize, bool bootstrap)
{
  std::chrono::system_clock::time_point start6 = std::chrono::system_clock::now();
  const FHEcontext& context = secKey.getContext();
  const EncryptedArray& ea = *(context.ea);
  long mask = (outSize? ((1L<<outSize)-1) : -1);

  long pa = RandomBits_long(bitSize);
  
  cout<<"star timing... pa is, slots "<<pa<<ea.size()<<endl; 
  vector<Ctxt> enca(bitSize2,Ctxt(secKey));

  for (int i=0; i<bitSize2; i++) {	
    secKey.Encrypt(enca[i], ZZX(pa));  
  }	
  
  ZZX PP;

  Ctxt eSum(secKey);
  eSum=enca[0];
  for (int k=1; k<bitSize2;k++)
  {
  	eSum+=(enca[k]);
  }
   vector<long> result;
   secKey.Decrypt(PP,eSum);	  
	long long pSum = (long long)pa;
  
  if(PP==pSum){
   cout << "sum succeeded: ";
    cout << pa<<"*"<<bitSize2<<"="<<pSum<<endl;
	}
	else
	{
		cout << "sum failed: ";
	}
	
  std::chrono::duration<double> sec = std::chrono::system_clock::now() - start6;
  std::cout << "time : " << sec.count() << " seconds" << std::endl;


}
