<?php
/**
 * This is a response template for  messages sent to browswer. Errors or infos.
 */
function createView($title = 'Error', $message = 'We experienced an error')
{
    $view = <<<EOD
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$title</title>
    <style>
    * {
        font-family: system-ui;
    }
    body{

        display: flex;
        justify-content: center;
        align-items: center;
        padding: 12% 2%;
    }
    div.message{
        
        height: auto;
        width: 100%;
        background-color: #e8e8e8;
        padding: 2% 3%;
        text-align: center;
        border-radius: 0.3em;
    }
    </style>
    </head>
    <body>
    <div class="message">
    <h3>$title</h3>
    <hr/>
    <br/>
    $message
    </div>
    </body>
    </html>
    EOD;
    return $view;
}