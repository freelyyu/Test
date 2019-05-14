//combine

#include <iostream>
#include <stdlib.h>
#include <cryptopp/rsa.h>
#include<cryptopp/sha3.h>
#include<string.h>
#include <NTL/ZZ.h>
#include <sys/time.h>
#include<NTL/ZZ_p.h>
#include <NTL/BasicThreadPool.h>
#include<stdexcept>
#include<string.h>

#include<stdio.h>
using namespace std;


long N_bf;

struct Proof
{
    std::vector<NTL::ZZ_p> commit;                      //Z_q
	NTL::ZZ_p challenge,response;                       //Z_p

};

double TimeInterval(timeval start, timeval end)
{
	return double(1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec) / 1000000;
}

Proof  ZKP(std::vector<NTL::ZZ_p> g, std::vector<NTL::ZZ_p> h,const NTL::ZZ_p w,const NTL::ZZ p,NTL::ZZ q)
{
    Proof pi;
    NTL::ZZ_p v;
    NTL::ZZ_p::init(p);
    NTL::random(v);

    if(g.size()!=h.size())
    {
        std::logic_error ex("parameter error");
        throw new std::exception(ex);
    }


    pi.commit.resize(g.size());   
    //std::cout <<"g"<< g.size() << std::endl;
    struct timeval start, end;
    gettimeofday(&start, NULL);   
    NTL_EXEC_RANGE(g.size(), first, last)
    for(int i=first;i<last;i++)
    {
        NTL::ZZ_p::init(q);
        NTL::power(pi.commit[i],g[i],rep(v));
    }
    NTL_EXEC_RANGE_END
    gettimeofday(&end, NULL);
	std::cout << "time1: " << TimeInterval(start, end) << std::endl;        //output time

    //--------------hash begin-----------------------
    gettimeofday(&start, NULL);  
    unsigned char *p1 = (unsigned char*)malloc(NumBytes(rep(g[0])) * 8);       //g, h, pi.commit are from z_q
	unsigned char *q1 = (unsigned char*)malloc(NumBytes(rep(h[0])) * 8);
	unsigned char *m1 = (unsigned char*)malloc(NumBytes(rep(pi.commit[0])) * 8);
    unsigned char *total= (unsigned char*)malloc((NumBytes(rep(pi.commit[0]))+NumBytes(rep(h[0]))+NumBytes(rep(pi.commit[0]))) * 8);
	
	BytesFromZZ(p1, rep(g[0]), NumBytes(rep(g[0])));
	BytesFromZZ(q1, rep(h[0]), NumBytes(rep(h[0])));
	BytesFromZZ(m1, rep(pi.commit[0]), NumBytes(rep(pi.commit[0])));
    std::cout << "p1" << p1 << std::endl;
    std::cout << "total" <<total<< std::endl;
    strcat(total,p1);
    std::cout << "total2" <<total<< std::endl;
    strcat(total,q1);
    strcat(total,m1);




	CryptoPP::SHA3_256 sha;  
    NTL::ZZ temp;  
	unsigned char digest[CryptoPP::SHA256::DIGESTSIZE];   
	sha.CalculateDigest(digest, (const unsigned char*)total, NumBytes(rep(g[0])));
	//sha.Update((const unsigned char*)q1, NumBytes(rep(h[0])));
	//sha.Update((const unsigned char*)m1, NumBytes(rep(pi.commit[0])));

    
    for(int i=1;i<g.size();i++)                       //for(i=1;i<N_bf;i++)
    {
        BytesFromZZ(p1, rep(g[i]), NumBytes(rep(g[i])));
	    BytesFromZZ(q1, rep(h[i]), NumBytes(rep(h[i])));
	    BytesFromZZ(m1, rep(pi.commit[i]), NumBytes(rep(pi.commit[i])));

        sha.Update((const unsigned char*)p1, NumBytes(rep(g[i])));
        sha.Update((const unsigned char*)q1, NumBytes(rep(h[i])));
	    sha.Update((const unsigned char*)m1, NumBytes(rep(pi.commit[i])));
    }
   
    sha.Final(digest);
    gettimeofday(&end, NULL);
	std::cout << "hash time2: " << TimeInterval(start, end) << std::endl;        //output time
    //--------------------------hash end-------------------
	ZZFromBytes(temp, digest, CryptoPP::SHA256::DIGESTSIZE);
    NTL::ZZ_p::init(p);
    pi.challenge=NTL::to_ZZ_p(temp);
	pi.response = (v  - (pi.challenge)* w); 

    free(p1);
    free(q1);
    free(m1);
    return pi;

}

bool Verify(std::vector<NTL::ZZ_p> g, std::vector<NTL::ZZ_p> h,NTL::ZZ p,NTL::ZZ q,Proof pi)
{
    //res[i] = g[i]^w*h[i]^c;
    std::vector<NTL::ZZ_p> res1, res2, res;

    if(g.size()!=h.size())
    {
        std::logic_error ex("parameter error");
        throw new std::exception(ex);
    }

    int N = g.size();
    res1.resize(N);
    res2.resize(N);
    res.resize(N); // might not need res
    
//------verify challenge by computing hash---------------
    unsigned char *p1 = (unsigned char*)malloc(NumBytes(rep(g[0])) * 8);       //g, h, pi.commit are from z_q
	unsigned char *q1 = (unsigned char*)malloc(NumBytes(rep(h[0])) * 8);
	unsigned char *m1 = (unsigned char*)malloc(NumBytes(rep(pi.commit[0])) * 8);
	
	BytesFromZZ(p1, rep(g[0]), NumBytes(rep(g[0])));
	BytesFromZZ(q1, rep(h[0]), NumBytes(rep(h[0])));
	BytesFromZZ(m1, rep(pi.commit[0]), NumBytes(rep(pi.commit[0])));

	CryptoPP::SHA3_256 sha;  
    NTL::ZZ temp1;  
    NTL::ZZ_p challengeNew;
	unsigned char digest[CryptoPP::SHA256::DIGESTSIZE];   
	sha.CalculateDigest(digest, (const unsigned char*)p1, NumBytes(rep(g[0])));
	sha.Update((const unsigned char*)q1, NumBytes(rep(h[0])));
	sha.Update((const unsigned char*)m1, NumBytes(rep(pi.commit[0])));

    
    for(int i=1;i<g.size();i++)                       //for(i=1;i<N_bf;i++)
    {
        BytesFromZZ(p1, rep(g[i]), NumBytes(rep(g[i])));
	    BytesFromZZ(q1, rep(h[i]), NumBytes(rep(h[i])));
	    BytesFromZZ(m1, rep(pi.commit[i]), NumBytes(rep(pi.commit[i])));

        sha.Update((const unsigned char*)p1, NumBytes(rep(g[i])));
        sha.Update((const unsigned char*)q1, NumBytes(rep(h[i])));
	    sha.Update((const unsigned char*)m1, NumBytes(rep(pi.commit[i])));
    }
   
    sha.Final(digest);
	ZZFromBytes(temp1, digest, CryptoPP::SHA256::DIGESTSIZE);
    NTL::ZZ_p::init(p);
    challengeNew=NTL::to_ZZ_p(temp1);
    if(pi.challenge!=challengeNew)
    {
        std::logic_error ex("verify error");
        throw new std::exception(ex);
        return false;
    }

//--------------------------------------------------


    bool ans = true;
    NTL_EXEC_RANGE(N, first, last)
    for(int i=first; i<last; i++)
    {
        if(ans == false)
            break;
        NTL::ZZ_p::init(q);
        NTL::power(res1[i],g[i],rep(pi.response));
        NTL::power(res2[i],h[i],rep(pi.challenge));
	    //res[i] = NTL::to_ZZ_p(rep((res1[i]*res2[i])) % q);   
        if(pi.commit[i] != res1[i] * res2[i])
        {
           ans = false;
        }
    
    }
	NTL_EXEC_RANGE_END

/*
    for(int i=0;i<N;i++)
    {
        if(pi.commit[i] != res[i])
        {
        return false;
        } 
        //std::cout << pi.commit[i] << std::endl;
        //std::cout << res[i] << std::endl;
    }
*/
	return ans;
}

int main()
{
    cin>>N_bf;
    N_bf=N_bf+1;
    std::vector<NTL::ZZ_p> g;
    g.resize(N_bf);
	NTL::ZZ p,q;
    NTL::ZZ_p w;
    p = NTL::GenGermainPrime_ZZ(128, 80);                    //128:bitlength
	q = 2 * p + 1;

    for(size_t i=0; i<N_bf;i++)
    {
        NTL::ZZ_p::init(q);
        NTL::random(g[i]);                                         //select g from Z_q，then double g.
	    g[i]*=g[i];
    }

    NTL::ZZ_p::init(p);
    NTL::random(w);                                       

    std::vector<NTL::ZZ_p> h;
    h.resize(N_bf);
    for(int i=0 ; i<N_bf; i++)
    {
        NTL::ZZ_p::init(q);
        NTL::power(h[i],g[i],rep(w));
    }

    bool flag;
    Proof pi;
    pi.commit.resize(N_bf);
    NTL::SetNumThreads(36);
    struct timeval start, end;
    gettimeofday(&start, NULL);                   
    //call ZKP
    pi=ZKP(g,h,w,p,q);
    //call Verify
    flag=Verify(g, h, p,q,pi);
    gettimeofday(&end, NULL);
	std::cout << "total time: " << TimeInterval(start, end) << std::endl;   //output time

    if(flag==true)
    std::cout << "pass" << std::endl;
    else
    std::cout << "fail" << std::endl;
}
