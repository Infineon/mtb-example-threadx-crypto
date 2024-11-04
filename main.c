#include <crypto.h>
#include "cyhal.h"
#include "cybsp.h"
#include "cy_retarget_io.h"

int main() {
    cy_rslt_t result;

    /* Initialize the device and board peripherals */
    result = cybsp_init();

    cyhal_syspm_lock_deepsleep();

    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }


    /* Initialize retarget-io to use the debug UART port */
    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX,
                                 CY_RETARGET_IO_BAUDRATE);
    /* retarget-io init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

   /* Enable global interrupts */
    __enable_irq();

    printf("***************************************************************************\n");
    printf("                         Cryptography Demonstration                        \n");
    printf("***************************************************************************\n\n");

    processInput();
    return 0;
}
/* [] END OF FILE */
