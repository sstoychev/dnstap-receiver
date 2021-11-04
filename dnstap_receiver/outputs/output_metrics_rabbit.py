import logging
import asyncio
import json
from dnstap_receiver.outputs.output_rabbitmq import RabbitMQ
from dnstap_receiver import statistics

clogger = logging.getLogger("dnstap_receiver.console")
metrics_logger = logging.getLogger("dnstap_receiver.output.metrics")

async def handle(output_cfg: dict, metrics: statistics.Statistics, start_shutdown: asyncio.Event):
    """stdout output handler"""
    # init logger

    rabbitmq = RabbitMQ(output_cfg=output_cfg)
    clogger.info("Output handler: metrics_rabbitmq: Enabled")

    stats_cfg = output_cfg['statistics']

    shutdown_wait_task = asyncio.create_task(start_shutdown.wait())
    sleep_task = asyncio.create_task(asyncio.sleep(stats_cfg["interval"]))

    while not start_shutdown.is_set():
        done, _ = await asyncio.wait(
            [shutdown_wait_task, sleep_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if shutdown_wait_task in done:
            sleep_task.cancel()
            return

        sleep_task = asyncio.sleep(stats_cfg["interval"])

        msg = {}
        for stream in metrics.get_streams():
            if stream.bufq or stream.bufr or stream.bufi:
                msg[stream.name] = {
                    'bufq': dict(stream.bufq),
                    'bufr': dict(stream.bufr),
                    'bufi': dict(stream.bufi),
                }
        if msg:
            clogger.debug(json.dumps(msg, indent=4))
            rabbitmq.publish(json.dumps(msg))
        else:
            clogger.debug('Nothing to publish')

        # reset stats?
        if not stats_cfg["comulative"]:
            clogger.debug('resetting stats')
            metrics.reset()
    # tell producer to shut down
    clogger.info("Output handler: rabbitmq: Triggering producer shutdown")
    rabbitmq.close_connection()
