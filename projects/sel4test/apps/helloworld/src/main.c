/* Minimal helloworld rootserver for sel4test workspace */
#include <stdio.h>
#include <sel4/sel4.h>

int main(void)
{
    printf("Hello World from sel4 rootserver!\n");
    /* Keep the rootserver alive */
    while (1) {
        seL4_Yield();
    }
    return 0;
}
