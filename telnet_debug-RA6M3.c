/***********************************************************************************************************************
 * File Name    : net_thread_entry.c
 * Description  : This file contains the User Application code for the Ethernet + TCP/IP
 ***********************************************************************************************************************/
/***********************************************************************************************************************
 * DISCLAIMER
 * This software is supplied by Renesas Electronics Corporation and is only intended for use with Renesas products. No
 * other uses are authorized. This software is owned by Renesas Electronics Corporation and is protected under all
 * applicable laws, including copyright laws.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
 * THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED. TO THE MAXIMUM
 * EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES
 * SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR ANY REASON RELATED TO THIS
 * SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * Renesas reserves the right, without notice, to make changes to this software and to discontinue the availability of
 * this software. By using this software, you agree to the additional terms and conditions found by accessing the
 * following link:
 * http://www.renesas.com/disclaimer
 *
 * Copyright (C) 2019 Renesas Electronics Corporation. All rights reserved.
 ***********************************************************************************************************************/
#include "net_thread.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_Sockets.h"
#include "common_utils.h"
#include "usr_app.h"
#include "telnet.h"
/* Domain for the DNS Host lookup is used in this Example Project.
 * The project can be built with different *domain_name to validate the DNS client
 */
char *domain_name = USR_TEST_DOMAIN_NAME;

/* IP address of the PC or any Device on the LAN/WAN where the Ping request is sent.
 * Note: Users needs to change this according to the LAN settings of your Test PC or device
 * when running this project.
 */
//char *remote_ip_address = "132.158.142.140";
//char *remote_ip_address = "192.168.1.140";
char *remote_ip_address = USR_TEST_PING_IP;

#if( ipconfigUSE_DHCP != 0 )
   /* DHCP populates these IP address, Sub net mask and Gateway Address. So start with this is zeroed out values
    * The MAC address is Test MAC address.
    */
    static  uint8_t ucMACAddress[ 6 ]       = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static  uint8_t ucIPAddress[ 4 ]        = {RESET_VALUE};
    static  uint8_t ucNetMask[ 4 ]          = {RESET_VALUE};
    static  uint8_t ucGatewayAddress[ 4 ]   = {RESET_VALUE};
    static  uint8_t ucDNSServerAddress[ 4 ] = {RESET_VALUE};
#else
    /* Static IP configuration, when DHCP mode is not used for the Example Project.
     * This needs to be populated by the user according to the Network Settings of your LAN.
     * This sample address taken from the LAN where it is tested. This is different for different LAN.
     * get the Address using the PC IPconfig details.
     */
    static  uint8_t ucMACAddress[ 6 ]       = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    static  uint8_t ucIPAddress[ 4 ]        = {192, 168, 0, 52};
    static  uint8_t ucNetMask[ 4 ]          = {255, 255, 255, 0};
    static  uint8_t ucGatewayAddress[ 4 ]   = {192, 168, 0, 3};
    static  uint8_t ucDNSServerAddress[ 4 ] = {10, 60, 1, 2};
#endif


#if( ipconfigUSE_DHCP != 0 )
    extern NetworkAddressingParameters_t xNetworkAddressing;
    NetworkAddressingParameters_t xNd = {RESET_VALUE, RESET_VALUE, RESET_VALUE, RESET_VALUE, RESET_VALUE};
#endif

static TelnetClient_t *pxTelnetAddSocket( Telnet_t *pxTelnet );
static void vTelnetRemove( Telnet_t * pxTelnet, TelnetClient_t *pxClient );

uint32_t  dhcp_in_use   = 0x01;
uint32_t  usrPingCount  = RESET_VALUE;
ping_data_t ping_data   = {RESET_VALUE, RESET_VALUE, RESET_VALUE};
static uint32_t usr_print_ability = RESET_VALUE;

static Telnet_t myTelnet;
struct freertos_sockaddr peer_address;
char pcBuffer[ 129 ];

/*******************************************************************************************************************//**
 * @brief      Generates 32 bit Random number
 * @param[in]  void
 * @retval     Random Number
 **********************************************************************************************************************/
uint32_t ulRand()
{
    /* example of a 32-bit random number generator.
     * Here rand() returns a 15-bit number. so create 32 bit Random number using 15 bit rand()
     */
    uint32_t ulResult =
        ((((uint32_t) rand()) & 0x7fffuL)       ) |
        ((((uint32_t) rand()) & 0x7fffuL) << 15 ) |
        ((((uint32_t) rand()) & 0x0003uL) << 30 );
    return ulResult;
}

 /*******************************************************************************************************************//**
 * @brief      Generates 32 sequence number
 * @param[in]  Source IP, Source Port, Destination IP and Destination Port.
 * @retval     Sequence Number
 **********************************************************************************************************************/

uint32_t ulApplicationGetNextSequenceNumber(uint32_t ulSourceAddress, uint16_t usSourcePort, uint32_t ulDestinationAddress,
                                            uint16_t usDestinationPort)
{
    /* Here we need to get random number for the sequence number.
     * This is just for testing purpose, so software rand() is okay.
     * This can also be tied to the TRNG.
     */

     return((ulSourceAddress + ulDestinationAddress + usSourcePort + usDestinationPort) && ulRand());
}

/*******************************************************************************************************************//**
* @brief      Send ICMP Ping request  based on the user input IP Address.
* @param[in]  IP address to Ping
* @retval     Sequence Number
**********************************************************************************************************************/
BaseType_t vSendPing( const char *pcIPAddress)
{
uint32_t ulIPAddress = RESET_VALUE;

    /*
     * The pcIPAddress parameter holds the destination IP address as a string in
     * decimal dot notation (for example, “192.168.0.200”). Convert the string into
     * the required 32-bit format.
     */
    ulIPAddress = FreeRTOS_inet_addr(pcIPAddress);

    /*
     * Send a ping request containing 8 data bytes.  Wait (in the Blocked state) a
     * maximum of 100ms for a network buffer into which the generated ping request
     * can be written and sent.
     */
    return(FreeRTOS_SendPingRequest(ulIPAddress, 8, 100 / portTICK_PERIOD_MS));
}

/*******************************************************************************************************************//**
* @brief      User Hook for the Ping Reply. vApplicationPingReplyHook() is called by the TCP/IP
*             stack when the stack receives a ping reply.
* @param[in]  Ping reply status and Identifier
* @retval     None
**********************************************************************************************************************/
void vApplicationPingReplyHook( ePingReplyStatus_t eStatus, uint16_t usIdentifier )
{
    (void)  usIdentifier;

    switch( eStatus )
    {
        /* A valid ping reply has been received */
        case eSuccess    :
            ping_data.received++;
            break;
            /* A reply was received but it was not valid. */
        case eInvalidData :
        default:
            ping_data.lost++;
            break;
    }
}

/*******************************************************************************************************************//**
* @brief      This is the User Thread for the EP.
* @param[in]  Thread specific parameters
* @retval     None
**********************************************************************************************************************/
void net_thread_entry(void *pvParameters)
{
    BaseType_t status = pdFALSE;
    fsp_pack_version_t version = {RESET_VALUE};

    FSP_PARAMETER_NOT_USED (pvParameters);

    /* version get API for FLEX pack information */
    R_FSP_VersionGet (&version);

    /* Example Project information printed on the RTT */
    APP_PRINT (BANNER_INFO, EP_VERSION, version.major, version.minor, version.patch);

    /* Prints the Ethernet Configuration prior to the IP Init*/
    APP_PRINT(ETH_PREINIT);
    print_ipconfig();

    /* FreeRTOS IP Initialization: This init initializes the IP stack  */
    status = FreeRTOS_IPInit(ucIPAddress, ucNetMask, ucGatewayAddress, ucDNSServerAddress, ucMACAddress);

    if(pdFALSE == status)
    {
        APP_ERR_PRINT("FreeRTOS_IPInit Failed");
        APP_ERR_TRAP(status);
    }
    APP_PRINT(ETH_POSTINIT);

    while(true)
    {
        /* Check if Both the Ethernet Link and IP link are UP */
        if(SUCCESS == isNetworkUp())
        {
            /* usr_print_ability is added to avoid multiple UP messages or Down Messages repeating*/
            if(!(PRINT_UP_MSG_DISABLE & usr_print_ability))
            {
                APP_PRINT("\r\nNetwork is Up");

                usr_print_ability |= PRINT_UP_MSG_DISABLE;
            }

            if(!(PRINT_NWK_USR_MSG_DISABLE & usr_print_ability))
            {
#if( ipconfigUSE_DHCP != 0 )
                /* Display the New IP credentials obtained from the DHCP server */
                updateDhcpResponseToUsr();
#endif
                /* Updated IP credentials on to the RTT console */
                print_ipconfig();
                xTelnetCreate( &myTelnet, TELNET_PORT_NUMBER );
                /*DNS lookup for the Domain name requested. This is Synchronous Activity */
                dnsQuerryFunc(domain_name);
            }
            if(!(PRINT_NWK_USR_MSG_DISABLE & usr_print_ability))
            {
                APP_PRINT("\r\nPinging %s:\r\n\r\n",(char *)remote_ip_address);
            }

            while (usrPingCount < USR_PING_COUNT)
            {
                /* Send a ICMP Ping request to the requested IP address
                 * USR_PING_COUNT (100) is used in this Example Project
                 * For Continuous testing the count can be increased to bigger number
                 */

                status =  vSendPing((char *)remote_ip_address);
                if(status != pdFALSE)
                {
                    ping_data.sent++;
                    APP_PRINT("!");
                }
                else
                {
                    ping_data.lost++;
                    APP_PRINT(".");
                }
                usrPingCount++;
                /* Add some delay between Pings */
                vTaskDelay(10);
            }

            if(!(PRINT_NWK_USR_MSG_DISABLE & usr_print_ability))
            {
                print_pingResult();
                usr_print_ability |= PRINT_NWK_USR_MSG_DISABLE;
            }
        }
        else
        {
            if(!(PRINT_DOWN_MSG_DISABLE & usr_print_ability))
            {
                 APP_PRINT("\r\nNetwork is Down");
                 usr_print_ability |= PRINT_DOWN_MSG_DISABLE;
            }
            else
            {
                 APP_PRINT(".");
            }
        }
        BaseType_t xResult = xTelnetRecv( &( myTelnet ), &( peer_address ), pcBuffer, sizeof pcBuffer );
                                                if( xResult > 0 )
                                                {
                                                    xResult = APP_PRINT( pcBuffer, sizeof pcBuffer, "Thank you\n" );
                                                    xTelnetSend( &( myTelnet ), &( peer_address ), pcBuffer, xResult );
                                                }
        vTaskDelay(100);
    }
}

/*******************************************************************************************************************//**
* @brief      This is the User Hook for the DHCP Response. xApplicationDHCPHook() is called by DHCP Client Code when DHCP
*             handshake messages are exchanged from the Server.
* @param[in]  Different Phases of DHCP Phases and the Offered IP Address
* @retval     Returns DHCP Answers.
**********************************************************************************************************************/
#if( ipconfigUSE_DHCP != 0 )
eDHCPCallbackAnswer_t xApplicationDHCPHook( eDHCPCallbackPhase_t eDHCPPhase,
                                            uint32_t ulIPAddress )
{
eDHCPCallbackAnswer_t eReturn = eDHCPContinue;
  /*
   * This hook is called in a couple of places during the DHCP process, as identified by the eDHCPPhase parameter.
   */
  switch( eDHCPPhase )
  {
    case eDHCPPhasePreDiscover  :
      /*
       *  A DHCP discovery is about to be sent out.  eDHCPContinue is returned to allow the discovery to go out.
       *  If eDHCPUseDefaults had been returned instead then the DHCP process would be stopped and the statically
       *  configured IP address would be used.
       *  If eDHCPStopNoChanges had been returned instead then the DHCP process would be stopped and whatever the
       *  current network configuration was would continue to be used.
       */
        break;

    case eDHCPPhasePreRequest  :
      /* An offer has been received from the DHCP server, and the offered IP address is passed in the ulIPAddress
       * parameter.
       */

        /*
         * The sub-domains don’t match, so continue with the DHCP process so the offered IP address is used.
         */
        /* Update the Structure, the DHCP state Machine is not updating this */
        xNetworkAddressing.ulDefaultIPAddress = ulIPAddress;
        dhcp_in_use = 1;
      break;

    default :
      /*
       * Cannot be reached, but set eReturn to prevent compiler warnings where compilers are disposed to generating one.
       */
        break;
  }

  return eReturn;
}
#endif


/*******************************************************************************************************************//**
 * @brief      Prints the Ping response on to the RTT console
 * @param[in]  void
 * @retval     None
 **********************************************************************************************************************/
void print_pingResult(void)
{
    APP_PRINT("\r\n \r\nPing Statistics for %s :\r\n",(char *)remote_ip_address);
    APP_PRINT("\r\nPackets: Sent  = %02d, Received = %02d, Lost = %02d \r\n",ping_data.sent,ping_data.received,ping_data.lost);
}

/*******************************************************************************************************************//**
 * @brief      Creates and prints the the IP configuration to display on the RTT console
 * @param[in]  void
 * @retval     None
 **********************************************************************************************************************/

void print_ipconfig(void)
{
#if( ipconfigUSE_DHCP != 0 )
    if(dhcp_in_use)
    {
        ucNetMask[3] = (uint8_t)((xNd.ulNetMask & 0xFF000000) >> 24);
        ucNetMask[2] = (uint8_t)((xNd.ulNetMask & 0x00FF0000) >> 16);
        ucNetMask[1] = (uint8_t)((xNd.ulNetMask & 0x0000FF00) >> 8);
        ucNetMask[0] = (uint8_t)(xNd.ulNetMask & 0x000000FF);

        ucGatewayAddress[3] = (uint8_t)((xNd.ulGatewayAddress & 0xFF000000)>> 24);;
        ucGatewayAddress[2] = (uint8_t)((xNd.ulGatewayAddress & 0x00FF0000)>> 16);
        ucGatewayAddress[1] = (uint8_t)((xNd.ulGatewayAddress & 0x0000FF00)>> 8);
        ucGatewayAddress[0] = (uint8_t)(xNd.ulGatewayAddress & 0x000000FF);

        ucDNSServerAddress[3] = (uint8_t)((xNd.ulDNSServerAddress & 0xFF000000)>> 24);
        ucDNSServerAddress[2] = (uint8_t)((xNd.ulDNSServerAddress & 0x00FF0000)>> 16);
        ucDNSServerAddress[1] = (uint8_t)((xNd.ulDNSServerAddress & 0x0000FF00)>> 8);
        ucDNSServerAddress[0] = (uint8_t)(xNd.ulDNSServerAddress & 0x000000FF);

        ucIPAddress[3] = (uint8_t)((xNd.ulDefaultIPAddress & 0xFF000000) >> 24);
        ucIPAddress[2] = (uint8_t)((xNd.ulDefaultIPAddress & 0x00FF0000) >> 16);
        ucIPAddress[1] = (uint8_t)((xNd.ulDefaultIPAddress & 0x0000FF00) >> 8);
        ucIPAddress[0] = (uint8_t)(xNd.ulDefaultIPAddress & 0x000000FF);
    }
#endif
    APP_PRINT("\r\nEthernet adapter for Renesas "KIT_NAME":\r\n")

    APP_PRINT("\tDescription . . . . . . . . . . . : Renesas "KIT_NAME" Ethernet\r\n");
    APP_PRINT("\tPhysical Address. . . . . . . . . : %02x-%02x-%02x-%02x-%02x-%02x\r\n",
            ucMACAddress[0],ucMACAddress[1],ucMACAddress[2],ucMACAddress[3],ucMACAddress[4],ucMACAddress[5]);
    APP_PRINT("\tDHCP Enabled. . . . . . . . . . . : %s\r\n",dhcp_in_use?"Yes":"No")
    APP_PRINT("\tIPv4 Address. . . . . . . . . . . : %d.%d.%d.%d\r\n",ucIPAddress[0],ucIPAddress[1],ucIPAddress[2],ucIPAddress[3]);
    APP_PRINT("\tSubnet Mask . . . . . . . . . . . : %d.%d.%d.%d\r\n",ucNetMask[0],ucNetMask[1],ucNetMask[2],ucNetMask[3]);
    APP_PRINT("\tDefault Gateway . . . . . . . . . : %d.%d.%d.%d\r\n",ucGatewayAddress[0],ucGatewayAddress[1],ucGatewayAddress[2],ucGatewayAddress[3]);
    APP_PRINT("\tDNS Servers . . . . . . . . . . . : %d.%d.%d.%d\r\n",ucDNSServerAddress[0],ucDNSServerAddress[1],ucDNSServerAddress[2],ucDNSServerAddress[3]);
}


/*******************************************************************************************************************//**
 * @brief      DNS Query for the requested Domain name.  Uses the FreeRTOS Client API  FreeRTOS_gethostbyname
 *             to get the IP address for the domain name
 * @param[in]  Domain name
 * @retval     None
 **********************************************************************************************************************/
void dnsQuerryFunc(char *domain)
{
    uint32_t ulIPAddress = RESET_VALUE;
    int8_t cBuffer[ 16 ] = {RESET_VALUE};

    /* Lookup the IP address of the FreeRTOS.org website. */
    ulIPAddress = FreeRTOS_gethostbyname((char*)domain);

    if( ulIPAddress != 0 )
    {
        /* Convert the IP address to a string. */
        FreeRTOS_inet_ntoa( ulIPAddress, ( char * ) cBuffer);

        /* Print out the IP address obtained from the DNS lookup. */
        APP_PRINT ("\r\nDNS Lookup for \"www.freertos.org\" is      : %s  \r\n", cBuffer);
    }
    else
    {
        APP_PRINT ("\r\nDNS Lookup failed for \"www.freertos.org\" \r\n");
    }
}

/*******************************************************************************************************************//**
 * @brief      This Function checks the Network status (Both Ethernet and IP Layer). If the Network is down
 *             the Application will not send any data on the network.
 * @param[in]  None
 * @retval     Network Status
 **********************************************************************************************************************/
uint32_t isNetworkUp(void)
{
    fsp_err_t  eth_link_status = FSP_ERR_NOT_OPEN;
    BaseType_t networkUp = pdFALSE;
    uint32_t network_status = (IP_LINK_UP | ETHERNET_LINK_UP);

    networkUp = FreeRTOS_IsNetworkUp();
    eth_link_status = R_ETHER_LinkProcess(g_ether0.p_ctrl);

    if((FSP_SUCCESS == eth_link_status) && (pdTRUE == networkUp))
    {
        return network_status;
    }
    else
    {
        if(FSP_SUCCESS != eth_link_status)
        {
            network_status |= ETHERNET_LINK_DOWN;
        }
        else if(FSP_SUCCESS == eth_link_status)
        {
            network_status |= ETHERNET_LINK_UP;
        }

        if(pdTRUE != networkUp)
        {
             network_status |= IP_LINK_DOWN;
        }
        else if(pdTRUE == networkUp)
        {
             network_status |= IP_LINK_UP;
        }
        return network_status;
    }
}

/*******************************************************************************************************************//**
 * @brief      Update the DHCP info to the User data structure.
 * @param[in]  None
 * @retval     None
 **********************************************************************************************************************/
#if( ipconfigUSE_DHCP != 0 )
void updateDhcpResponseToUsr(void)
{
    if(dhcp_in_use)
    {
        memcpy(&xNd, &xNetworkAddressing, sizeof(xNd));
    }
}
#endif
/*******************************************************************************************************************//**
 * @brief      DHCP Hook function to populate the user defined Host name for the Kit.
 * @param[in]  None
 * @retval     Hostname
 **********************************************************************************************************************/
#if( ipconfigDHCP_REGISTER_HOSTNAME == 1 )
const char *pcApplicationHostnameHook(void)
{
    return KIT_NAME;
}
#endif
/*-------------------------------------------------------------*/
static TelnetClient_t *pxTelnetAddSocket( Telnet_t *pxTelnet )
{
TelnetClient_t *pxNewClient;

    pxNewClient = pvPortMalloc( sizeof( *pxNewClient ) );
    if( pxNewClient != NULL )
    {
        memset( pxNewClient, '\0', sizeof( *pxNewClient ) );

        if( pxTelnet->xClients == NULL )
        {
            pxTelnet->xClients = pxNewClient;
        }
        else
        {
        TelnetClient_t *pxClient;

            pxClient = pxTelnet->xClients;
            while( pxClient->pxNext != NULL )
            {
                pxClient = pxClient->pxNext;
            }
            pxClient->pxNext = pxNewClient;
        }
    }
    return pxNewClient;
}
/*-----------------------------------------------------------*/

static void vTelnetRemove( Telnet_t * pxTelnet, TelnetClient_t *pxClient )
{
TelnetClient_t *pxList;

    if( pxTelnet->xClients == pxClient )
    {
        pxTelnet->xClients = pxClient->pxNext;
    }
    else
    {
        pxList = pxTelnet->xClients;
        do
        {
            if( pxList->pxNext == pxClient )
            {
                pxList->pxNext = pxClient->pxNext;
                break;
            }
            pxList = pxList->pxNext;
        } while( pxList != NULL );
    }
    FreeRTOS_closesocket( pxClient->xSocket );
    vPortFree( pxClient );
}

/*-----------------------------------------------------------*/

BaseType_t xTelnetSend( Telnet_t * pxTelnet, struct freertos_sockaddr *pxAddress, const char *pcBuffer, BaseType_t xLength )
{
TelnetClient_t *pxClient, *pxNext;
BaseType_t xResult = 0;

    pxClient = pxTelnet->xClients;
    while( pxClient != NULL )
    {
        /* Make a copy of pxNext, because pxClient might be deleted in case send() failes. */
        pxNext = pxClient->pxNext;

        /* Send to all, or send to a specific IP/port address. */
        if( ( pxAddress == NULL ) ||
            ( ( pxAddress->sin_addr == pxClient->xAddress.sin_addr ) && ( pxAddress->sin_port == pxClient->xAddress.sin_port ) ) )
        {
            xResult = FreeRTOS_send( pxClient->xSocket, pcBuffer, xLength, 0 );
            if( ( xResult < 0 ) && ( xResult != -pdFREERTOS_ERRNO_EAGAIN ) && ( xResult != -pdFREERTOS_ERRNO_EINTR ) )
            {
                FreeRTOS_printf( ( "xTelnetSend: client %p disconnected (rc %d)\n", pxClient->xSocket, ( int )xResult ) );
                vTelnetRemove( pxTelnet, pxClient );
            }
            if( pxAddress != NULL )
            {
                break;
            }
        }
        pxClient = pxNext;
    }

    return xResult;
}

/*-----------------------------------------------------------*/

BaseType_t xTelnetRecv( Telnet_t * pxTelnet, struct freertos_sockaddr *pxAddress, char *pcBuffer, BaseType_t xMaxLength )
{
Socket_t xSocket;
#if( ipconfigUSE_IPv6 != 0 )
struct freertos_sockaddr6 xAddress;
struct freertos_sockaddr *xAddress4 = ( struct freertos_sockaddr * ) &( xAddress );
#else
struct freertos_sockaddr xAddress;
struct freertos_sockaddr *xAddress4 = ( struct freertos_sockaddr * ) &( xAddress );
#endif
socklen_t xSize = sizeof( xAddress );
TelnetClient_t *pxClient, *pxNextClient;
BaseType_t xResult = 0;

    if( pxTelnet->xParentSocket != NULL )
    {
        xAddress.sin_len = sizeof( xAddress );
        xAddress.sin_family = FREERTOS_AF_INET;

        xSocket = FreeRTOS_accept( pxTelnet->xParentSocket, ( struct freertos_sockaddr * ) &xAddress, &xSize );
        if( ( xSocket != NULL ) && ( xSocket != FREERTOS_INVALID_SOCKET ) )
        {
            #if( ipconfigUSE_IPv6 != 0 )
            if( xAddress.sin_family == FREERTOS_AF_INET6 )
            {
            struct freertos_sockaddr6 *pxAddress6 = ( struct freertos_sockaddr6 * ) &( xAddress );
                FreeRTOS_printf( ( "xTelnetRead: new client from %pip:%u\n",
                    pxAddress6->sin_addrv6.ucBytes,
                    ( unsigned )FreeRTOS_ntohs( pxAddress6->sin_port ) ) );
            }
            else
            #endif
            {
                FreeRTOS_printf( ( "xTelnetRead: new client from %xip:%u\n",
                    ( unsigned )FreeRTOS_ntohl( xAddress4->sin_addr ),
                    ( unsigned )FreeRTOS_ntohs( xAddress4->sin_port ) ) );
            }
            pxClient = pxTelnetAddSocket( pxTelnet );
            if( pxClient != NULL )
            {
                pxClient->xSocket = xSocket;
                memcpy( &pxClient->xAddress, &xAddress, sizeof( pxClient->xAddress ) );
            }
        }
        pxClient = pxTelnet->xClients;
        while( pxClient != NULL )
        {
            /* Make a copy of pxNext, because pxClient might be deleted in case recv() fails. */
            pxNextClient = pxClient->pxNext;
            xSocket = pxClient->xSocket;

            xResult = FreeRTOS_recv( xSocket, pcBuffer, xMaxLength, 0 );
            if( xResult > 0 )
            {
                if( pxAddress != NULL )
                {
                    /* Return the address of the remote client. */
                    memcpy( pxAddress, &pxClient->xAddress, sizeof( *pxAddress ) );
                }
                break;
            }
            if( ( xResult < 0 ) && ( xResult != -pdFREERTOS_ERRNO_EAGAIN ) && ( xResult != -pdFREERTOS_ERRNO_EINTR ) )
            {
            FreeRTOS_printf( ( "xTelnetRead: client %p disconnected (rc %d)\n", xSocket, ( int )xResult ) );
                vTelnetRemove( pxTelnet, pxClient );
            }
            pxClient = pxNextClient;
        }
    }

    return xResult;
}
/*---------------------------------------------------------------*/
#if( ipconfigDNS_USE_CALLBACKS != 0 )
    void vOnTCPConnected( Socket_t xSocket, BaseType_t ulConnected )
    {
        FreeRTOS_printf( ( "vOnTCPConnected (%p, %ld)\n", xSocket, ulConnected ) );
    }
    BaseType_t vOnTCPReceived( Socket_t xSocket, void * pData, size_t xLength )
    {
        ( void ) xSocket;
        FreeRTOS_printf( ( "vOnTCPReceived (%p, %d)\n", pData, xLength ) );
        return 1U;
    }
#endif
/*---------------------------------------------------------------*/
BaseType_t xTelnetCreate( Telnet_t * pxTelnet, BaseType_t xPortNr )
{
BaseType_t xSendTimeOut = 100U;//portMAX_DELAY;
BaseType_t xRecvTimeOut = 10;
struct freertos_sockaddr xBindAddress;
BaseType_t xResult = 0;

    memset( pxTelnet, '\0', sizeof( *pxTelnet ) );

    /* Attempt to open the socket. */
    pxTelnet->xParentSocket = FreeRTOS_socket( FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP );
    if( ( pxTelnet->xParentSocket == FREERTOS_INVALID_SOCKET ) || ( pxTelnet->xParentSocket == NULL ) )
    {
        xResult = -pdFREERTOS_ERRNO_ENOMEM;
        /* Don't like the value 'FREERTOS_INVALID_SOCKET'. */
        pxTelnet->xParentSocket = NULL;
    }
    else
    {
        /* Set the time-outs for both sending and receiving data to zero. */
        xResult = FreeRTOS_setsockopt( pxTelnet->xParentSocket, 0, FREERTOS_SO_RCVTIMEO, &xRecvTimeOut, sizeof( xRecvTimeOut ) );
        xResult = FreeRTOS_setsockopt( pxTelnet->xParentSocket, 0, FREERTOS_SO_SNDTIMEO, &xSendTimeOut, sizeof( xSendTimeOut ) );

        #if( ipconfigDNS_USE_CALLBACKS != 0 )
        {
            F_TCP_UDP_Handler_t xHandler;
            memset( &( xHandler ), 0, sizeof( xHandler ) );
            xHandler.pxOnTCPConnected = vOnTCPConnected;
            FreeRTOS_setsockopt( pxTelnet->xParentSocket, 0, FREERTOS_SO_TCP_CONN_HANDLER, &( xHandler ), sizeof( xHandler ) );

            /* When you set the TCP_RECV_HANDLER, telnet won't work properly because the incoming
            data won't be available for the calls to FreeRTOS_recv().
            */
            #if 0
            xHandler.pxOnTCPReceive = vOnTCPReceived;
            FreeRTOS_setsockopt( pxTelnet->xParentSocket, 0, FREERTOS_SO_TCP_RECV_HANDLER, &( xHandler ), sizeof( xHandler ) );
            #endif /* 0 */
        }
        #endif /* ( ipconfigDNS_USE_CALLBACKS != 0 ) */

        if( xResult >= 0 )
        {
            xBindAddress.sin_addr = 0;
            xBindAddress.sin_port = FreeRTOS_htons( xPortNr );
            xResult = FreeRTOS_bind( pxTelnet->xParentSocket, &xBindAddress, sizeof( xBindAddress ) );
            if( xResult >= 0 )
            {
                /* Limit the maximum number of simultaneous clients. */
                xResult = FreeRTOS_listen( pxTelnet->xParentSocket, TELNET_MAX_CLIENT_COUNT );
            }
        }
    }

    FreeRTOS_printf( ( "xTelnetCreate: socket created: rc %ld port %u\n", xResult, ( unsigned )xPortNr ) );

    return xResult;
}
/*-----------------------------------------------------------*/
