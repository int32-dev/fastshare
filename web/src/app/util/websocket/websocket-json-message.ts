export class WebsocketJsonMessage<T> {
  public static fromWebsocketMessage<T>(
    event: MessageEvent
  ): WebsocketJsonMessage<T> {
    if (typeof event.data !== 'string') {
      throw new Error('Expected string message');
    }

    const parts = event.data.split('\n', 2);
    if (parts.length != 2) {
      throw new Error('Invalid message format');
    }

    const data = JSON.parse(parts[1]);

    return new WebsocketJsonMessage<T>(parts[0], data);
  }

  constructor(public route: string, public payload: T) {}
}
