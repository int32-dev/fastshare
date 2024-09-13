export class UrlHelper {
    public static buildUrl(params: URLSearchParams): string {
        const uri = new URL(window.location.href);
        uri.protocol = window.location.protocol == 'https:' ? 'wss' : 'ws';
        uri.hostname = window.location.hostname;
        uri.port = window.location.port == '4200' ? '8080' : window.location.port;
        uri.pathname = '/ws';
        uri.search = params.toString();

        return uri.toString();
    }
}
