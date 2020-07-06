<?php

namespace App;

use Illuminate\Support\Fluent;

class Partner
{
    public $name;
    public $clientId;

    public function __construct(array $configData)
    {
        $data = new Fluent($configData);

        $this->setClientId($data->get('client_id'));
        $this->setName($data->get('name'));
    }

    private function setName($name)
    {
        if (is_null($name) || empty($name)) {
            throw new \Exception('Invalid partner parameter: name');
        }

        $this->name = $name;
    }

    private function setClientId($clientId)
    {
        if (is_null($clientId) || empty($clientId)) {
            throw new \Exception('Invalid partner parameter: client_id');
        }

        $this->clientId = $clientId;
    }
}
