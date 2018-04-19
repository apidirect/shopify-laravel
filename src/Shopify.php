<?php

namespace Bryanyeh\Shopify;

use GuzzleHttp\Client;
use Bryanyeh\Shopify\Exceptions\InvalidMethodRequestException;

class Shopify
{
    protected $key;
    protected $secret;
    protected $scopes;
    protected $shop;
    protected $client;
    protected $token;

    public function __construct(Client $client)
    {
        $this->client = $client;
        $this->key = config('shopify.key');
        $this->secret = config('shopify.secret');
        $this->scopes = config('shopify.scopes');
    }

    /**
     * Initialize the shopify client
     *
     * @param string $url
     * @param string $access_token
     * @return void
     */
    public function init(string $url,string $access_token=null)
    {
        $shopUrl = parse_url($url);
        $shopUrl = $shopUrl['host'] ?? $shopUrl['path'];

        $this->shop = $shopUrl;
        $this->token = $access_token;

        return $this;
    }

    /**
     * Get the shopify oauth link
     *
     * @param string $redirect_url
     * @return string
     */
    public function install(string $redirect_url=''): string
    {
        $scope = implode(",", $this->scopes);
        $nonce = str_random(20);
        session(['nonce'=> $nonce]);
        return "https://{$this->shop}/admin/oauth/authorize?client_id={$this->key}&scope={$scope}&redirect_uri={$redirect_url}&state={$nonce}";
    }

    /**
     * Exchange the temp code for a perm access token
     *
     * @param string $code
     * @return void
     */
    public function getAccessToken(string $code)
    {
        $uri = "/admin/oauth/access_token";
        $payload = ["client_id" => $this->key, 'client_secret' => $this->secret, 'code' => $code];
        return $this->request('POST', $uri,$payload) ?? '';
    }


    public function __call($method, $args)
    {
        $method = strtoupper($method);
        $allowedMethods = ['POST','GET','PUT','DELETE'];

        if(!in_array($method,$allowedMethods)){
            throw new InvalidMethodRequestException();
        }
        return $this->request($method,trim($args[0]),$args[1] ?? []);
    }

    /**
     * Do request with Guzzle
     *
     * @param string $method
     * @param string $uri
     * @param array $payload
     * @return array
     */
    private function request(string $method, string $uri, array $payload): array
    {
        $url = "https://{$this->shop}{$uri}";
        // $url = "https://{$this->key}:{$this->token}@{$this->shop}{$uri}";
        $params = [
                'exceptions' => false,
                'json' => $payload,
                'headers' => $this->token ? ['X-Shopify-Access-Token' =>$this->token, 'Content-Type' => 'application/json'] : []
        ];

        $response = $this->client->request(
            $method, 
            $url,
            $params
        );

        if( $uri !== '/admin/oauth/access_token' ) {
          $shopifyResponse = $this->shopify($uri, $method, $payload);
          return $shopifyResponse;
        }

        return array_merge([
            'statusCode' => $response->getStatusCode(),
            'reasonPhrase' => $response->getReasonPhrase(),
            'callLimit' => $response->hasHeader('HTTP_X_SHOPIFY_SHOP_API_CALL_LIMIT') ? $response->getHeaders()['HTTP_X_SHOPIFY_SHOP_API_CALL_LIMIT'][0] : '',
        ],json_decode($response->getBody(),true));
    }

    // THESE FUNCTIONS ARE FROM ATB
    private function shopify($api_call,$method=null,$data=null){
     
      $shopify = $this->call_shopify($api_call,$method,$data);
     
      if ( !empty($shopify->errors) ) {
        sleep(1);
        $shopify = $this->call_shopify($api_call,$method,$data);

      }

      $debug = array('call'=>$api_call,'method'=>$method,'data'=>$data,'response'=>$shopify);

      return $shopify;
    }


    private function call_shopify($api_call,$method='GET',$data=null){

      global $model;

      $child_parent = array(
        'articles' => 'blogs',
      );

      if( isset( $child_parent[$api_call] ) ){
        if( isset( $data['parent_id'] ) ){
          $api_call = $child_parent[$api_call] . '/' . $data['parent_id'] . '/' . $api_call;
        }
      }
      
      // $url = 'https://'.$model->shopify->api_key.':'.$model->shopify->api_password.'@'.$model->shopify->shop_id.'.myshopify.com/admin/'.$api_call.'.json';
      $url = 'https://'.$this->key.':'.$this->token.'@'.$this->shop.$api_call;

      if($method == 'GET' && count($data))
        $url.= '?' . http_build_query($data);

      $session = curl_init( $url );

      //curl_setopt($session, CURLOPT_URL, $url);
      curl_setopt($session, CURLOPT_HEADER, false);
      curl_setopt($session, CURLOPT_RETURNTRANSFER, true);
      if($method) {
        curl_setopt($session, CURLOPT_CUSTOMREQUEST, $method);
      }
      if($data) {
        $data_json = json_encode( $data );

        if($method == 'GET' && count($data)){
          curl_setopt($session, CURLOPT_HTTPGET, 1); 
        } else if($method == 'POST'){
          curl_setopt($session, CURLOPT_HTTPHEADER, array(                                                                          
          'Content-Type: application/json',                                                                               
          ));
          curl_setopt($session, CURLOPT_POSTFIELDS, $data_json); 
        }else if( $method == 'PUT' ){

          curl_setopt($session, CURLOPT_HTTPHEADER, array('X-HTTP-Method-Override: POST') );
          curl_setopt($session, CURLOPT_POSTFIELDS, $data_json);
          curl_setopt($session, CURLOPT_CUSTOMREQUEST, 'PUT');
          curl_setopt($session, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        }
      }

      // if(ereg("^(https)",$url)) curl_setopt($session,CURLOPT_SSL_VERIFYPEER,false);
      if(preg_match('/^(https)/',$url)) {
        curl_setopt($session,CURLOPT_SSL_VERIFYPEER,false);
      } 
      // this function is called by curl for each header received
      $headers = [];
      curl_setopt($session, CURLOPT_HEADERFUNCTION,
        function($curl, $header) use (&$headers)
        {
          $len = strlen($header);
          $header = explode(':', $header, 2);
          if (count($header) < 2) // ignore invalid headers
            return $len;

          $name = strtolower(trim($header[0]));
          if (!array_key_exists($name, $headers))
            $headers[$name] = [trim($header[1])];
          else
            $headers[$name][] = trim($header[1]);

          return $len;
        }
      );

      $response = curl_exec($session);
      $httpcode = curl_getinfo($session, CURLINFO_HTTP_CODE);
      $call_limit = ( isset($headers['http_x_shopify_shop_api_call_limit']) && isset($headers['http_x_shopify_shop_api_call_limit'][0]) ) ? $headers['http_x_shopify_shop_api_call_limit'][0] : '';
      // Check for errors and display the error message
      $error_message = '';
      if($errno = curl_errno($session)) {
          $error_message = curl_strerror($errno);
          echo "{$errno}:\n {$error_message}";
      }

      $response = json_decode($response);
      curl_close($session);

      return array_merge([
            'statusCode' => $httpcode,
            'reasonPhrase' => $error_message,
            'callLimit' => $call_limit,
        ],json_decode(json_encode($response),true));

    }

}

