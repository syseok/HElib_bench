
#include <NTL/lzz_pXFactoring.h>

#include <sstream>
#include <sys/time.h>


#include <iostream>
#include <cassert>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <NTL/BasicThreadPool.h>

#include <chrono>

#include "EncryptedArray.h"
#include "FHE.h"

#include "intraSlot.h"
#include "binaryArith.h"
#include "ArgMap.h"


using namespace NTL;
using namespace std;


void getCofactor(vector<vector<Ctxt>> A, vector<vector<Ctxt>> temp, int p, int q, int n) 
{ 
    int i = 0, j = 0; 
  
    // Looping for each element of the matrix 
    for (int row = 0; row < n; row++) 
    { 
        for (int col = 0; col < n; col++) 
        { 
            //  Copying into temporary matrix only those element 
            //  which are not in given row and column 
            if (row != p && col != q) 
            { 
                temp[i][j++] = A[row][col]; 
  
                // Row is filled, so increase row index and 
                // reset col index 
                if (j == n - 1) 
                { 
                    j = 0; 
                    i++; 
                } 
            } 
        } 
    } 
} 
  
/* Recursive function for finding determinant of matrix. 
   n is current dimension of A[][]. */
Ctxt determinant(vector<vector<Ctxt>> A, int n, int NN,const FHEPubKey& publicKey ) 
{ 

    Ctxt D(publicKey); // Initialize result 
  
    //  Base case : if matrix contains single element 
    if (n == 1) 
        return A[0][0]; 
  
    vector<vector<Ctxt>> temp(NN,vector<Ctxt>(NN,Ctxt(publicKey)));
     // To store cofactors 
  
    int sign = 1;  // To store sign multiplier 
  
     // Iterate for each element of first row 
    for (int f = 0; f < n; f++) 
    { 
        // Getting Cofactor of A[0][f] 
        // cout << "f is... "<<f << endl;
        getCofactor(A, temp, 0, f, n); 
        Ctxt temp2(publicKey);
        temp2 = A[0][f];
        temp2 *=  determinant(temp, n - 1,NN,publicKey);
        if(sign==-1)
          temp2.negate();

        D += temp2; 
  
        // terms are to be added with alternate sign 
        sign = -sign; 
    } 
  
    return D; 
} 
  
// Function to get adjoint of A[N][N] in adj[N][N]. 
void adjoint(vector<vector<Ctxt>> A, vector<vector<Ctxt>> adj,int NN, const FHEPubKey& publicKey) 
{ 
    // if (NN == 1) 
    // { 
    //     adj[0][0] = 1; 
    //     return; 
    // } 
    cout << "adjoint start" << endl;
    // temp is used to store cofactors of A[][] 
    int sign = 1;
    vector<vector<Ctxt>> temp(NN,vector<Ctxt>(NN,Ctxt(publicKey)));
  
    for (int i=0; i<NN; i++) 
    { 
        for (int j=0; j<NN; j++) 
        { 
            // Get cofactor of A[i][j] 
            getCofactor(A, temp, i, j, NN); 
  
            // sign of adj[j][i] positive if sum of row 
            // and column indexes is even. 
            sign = ((i+j)%2==0)? 1: -1; 
  
            // Interchanging rows and columns to get the 
            // transpose of the cofactor matrix 
            // cout << "adj[j][i] is ... "<<j<<" "<<i << endl;
            adj[j][i] = (determinant(temp, NN-1,NN,publicKey)); 

            if(sign==-1)
            {
              adj[j][i].negate();
            }
        } 
    } 
} 

int main(int argc, char **argv)
{
    /* On our trusted system we generate a new key
     * (or read one in) and encrypt the secret data set.
     */
   
    long m=0, p=2333, r=1; // Native plaintext space
                        // Computations will be 'modulo p'
    long L=16;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long security = 128;
    ZZX G;
    // m = FindM(security,L,c,p, d, 0, 0);
    m = 22;
    FHEcontext context(m, p, r);
    // initialize context
    buildModChain(context, L, c);
    // modify the context, adding primes to the modulus chain
    FHESecKey secretKey(context);
    // construct a secret key structure
    const FHEPubKey& publicKey = secretKey;
    // an "upcast": FHESecKey is a subclass of FHEPubKey

    //if(0 == d)
    G = context.alMod.getFactorsOverZZ()[0];

   secretKey.GenSecKey(w);
   // actually generate a secret key with Hamming weight w

   addSome1DMatrices(secretKey);
   cout << "Generated key" << endl;

   EncryptedArray ea(context, G);
   // constuct an Encrypted array object ea that is
   // associated with the given context and the polynomial G

   long nslots = ea.size();
   // cout << "nslots is ... "<<nslots<<endl;
   // long nslots = 5;

   // vector<long> v1;
   // for(int i = 0 ; i < nslots; i++) {
   //     v1.push_back(i*2);
   // }


   int row = 8;
   vector<vector<Ctxt>> ct1(row,vector<Ctxt>(row,Ctxt(publicKey)));
   vector<vector<Ctxt>> ct2(row,vector<Ctxt>(row,Ctxt(publicKey)));

   vector<vector<Ctxt>> ct1_trans(row,vector<Ctxt>(row,Ctxt(publicKey)));

   vector<vector<Ctxt>> xCovariance(row,vector<Ctxt>(row,Ctxt(publicKey)));

   vector<vector<Ctxt>> adjugateMatrix(row,vector<Ctxt>(row,Ctxt(publicKey)));


   vector<vector<Ctxt>> result(row,vector<Ctxt>(row,Ctxt(publicKey)));
   vector<vector<Ctxt>> result2(row,vector<Ctxt>(row,Ctxt(publicKey)));


   Ctxt temp_result(publicKey);





for(int k=0;k<5;k++)
{
   std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
// cout << "nslot is  " <<nslots<< endl;
   // cout << "Ctxt declaration done" << endl;
   vector<long> v1;
    for(int i = 0 ; i < nslots; i++) {
           v1.push_back(i*2);
       }
  for (int k=0;k<2;k++){
    for(int j=0; j <1;j++){
       ea.encrypt(ct1[j][k], publicKey, v1);
    }
  }

   // cout << "for 1 done " << endl;
     vector<long> v2;
    for(int i = 0 ; i < nslots; i++) {
           v2.push_back(200-i*3);
       }
   for (int k=0;k<1;k++){
    for(int j=0; j <1;j++){
       ea.encrypt(ct2[j][k], publicKey, v2);
    }
  }


  for (int i = 0; i<8; i++){
      for (int j = 0; j<8; j++){
        ct1_trans[j][i] = ct2[i][j]; //transpose * y
       }
   }
cout << "transpose done " << endl;


  adjoint(ct1, adjugateMatrix,8,publicKey);
  cout << "adjoint done " << endl;
    
  for (int i=0; i<8;i++)
   {
    for (int j=0;j<8;j++)
    {
      for(int k=0;k<8;k++)
      {
        temp_result = adjugateMatrix[i][j];
        temp_result *= result[j][k];
        result2[i][j] = temp_result; //adjugate * result1
      }
    }
   }

  


   vector<long> res;
    ea.decrypt(result2[0][0], secretKey, res);

    cout << "LinearRigression done " << endl;
std::chrono::duration<double> sec = std::chrono::system_clock::now() - start;
std::cout << "time : " << sec.count() << " seconds" << std::endl;



}






    return 0;
}